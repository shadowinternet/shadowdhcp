use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tracing::{info, warn};
use ureq::Agent;

use crate::analytics::events::DhcpEvent;
use crate::config::ClickHouseConfig;

const MAX_BATCH: usize = 256;
const MAX_BATCH_LATENCY: Duration = Duration::from_secs(3);
const RETRY_SLEEP: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Row shape sent to ClickHouse: event fields plus the server hostname.
/// `ip_version` from the enum tag is intentionally dropped — the destination
/// table is already known from the INSERT URL.
#[derive(Serialize)]
struct HostRow<'a, T: Serialize> {
    host_name: &'a str,
    #[serde(flatten)]
    inner: &'a T,
}

pub fn clickhouse_writer(cfg: ClickHouseConfig, rx: mpsc::Receiver<DhcpEvent>) {
    let agent: Agent = Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build()
        .into();

    let base = cfg.url.trim_end_matches('/');
    let url_v4 = format!(
        "{base}/?database={db}&query=INSERT+INTO+events_v4+FORMAT+JSONEachRow",
        db = cfg.database,
    );
    let url_v6 = format!(
        "{base}/?database={db}&query=INSERT+INTO+events_v6+FORMAT+JSONEachRow",
        db = cfg.database,
    );
    let auth = basic_auth_header(&cfg.user, &cfg.password);
    let host_name = cfg.hostname.unwrap_or_else(read_hostname);

    info!("Starting ClickHouse writer -> {base} (host_name={host_name:?})");

    let mut body_v4: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut body_v6: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut count_v4: usize;
    let mut count_v6: usize;
    let mut dropped: u64 = 0;

    loop {
        let first = match rx.recv() {
            Ok(ev) => ev,
            Err(_) => return,
        };

        body_v4.clear();
        body_v6.clear();
        count_v4 = 0;
        count_v6 = 0;
        append_row(
            &host_name,
            &first,
            &mut body_v4,
            &mut body_v6,
            &mut count_v4,
            &mut count_v6,
        );

        let start = Instant::now();
        while count_v4 + count_v6 < MAX_BATCH {
            let elapsed = start.elapsed();
            if elapsed >= MAX_BATCH_LATENCY {
                break;
            }
            match rx.recv_timeout(MAX_BATCH_LATENCY - elapsed) {
                Ok(ev) => append_row(
                    &host_name,
                    &ev,
                    &mut body_v4,
                    &mut body_v6,
                    &mut count_v4,
                    &mut count_v6,
                ),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    flush_with_retry(
                        &agent,
                        &url_v4,
                        &auth,
                        &body_v4,
                        count_v4,
                        &rx,
                        &mut dropped,
                    );
                    flush_with_retry(
                        &agent,
                        &url_v6,
                        &auth,
                        &body_v6,
                        count_v6,
                        &rx,
                        &mut dropped,
                    );
                    return;
                }
            }
        }

        flush_with_retry(
            &agent,
            &url_v4,
            &auth,
            &body_v4,
            count_v4,
            &rx,
            &mut dropped,
        );
        flush_with_retry(
            &agent,
            &url_v6,
            &auth,
            &body_v6,
            count_v6,
            &rx,
            &mut dropped,
        );

        if dropped > 0 {
            warn!("Dropped {dropped} DHCP events waiting for ClickHouse");
            dropped = 0;
        }
    }
}

fn append_row(
    host_name: &str,
    event: &DhcpEvent,
    body_v4: &mut Vec<u8>,
    body_v6: &mut Vec<u8>,
    count_v4: &mut usize,
    count_v6: &mut usize,
) {
    match event {
        DhcpEvent::V4(v4) => {
            let row = HostRow {
                host_name,
                inner: v4,
            };
            if serde_json::to_writer(&mut *body_v4, &row).is_ok() {
                body_v4.push(b'\n');
                *count_v4 += 1;
            }
        }
        DhcpEvent::V6(v6) => {
            let row = HostRow {
                host_name,
                inner: v6,
            };
            if serde_json::to_writer(&mut *body_v6, &row).is_ok() {
                body_v6.push(b'\n');
                *count_v6 += 1;
            }
        }
    }
}

/// POST `body` to `url`. On transport error or non-2xx, sleep and retry,
/// draining pending events from `rx` so the channel doesn't grow unbounded.
fn flush_with_retry(
    agent: &Agent,
    url: &str,
    auth: &str,
    body: &[u8],
    count: usize,
    rx: &mpsc::Receiver<DhcpEvent>,
    dropped: &mut u64,
) {
    if count == 0 {
        return;
    }
    loop {
        match agent
            .post(url)
            .header("Authorization", auth)
            .header("Content-Type", "application/x-ndjson")
            .send(body)
        {
            Ok(resp) if resp.status().is_success() => return,
            Ok(resp) => {
                warn!(
                    "ClickHouse returned HTTP {} for batch of {count}",
                    resp.status().as_u16()
                );
            }
            Err(e) => {
                warn!("ClickHouse POST failed for batch of {count}: {e}");
            }
        }
        while rx.try_recv().is_ok() {
            *dropped += 1;
        }
        std::thread::sleep(RETRY_SLEEP);
    }
}

fn basic_auth_header(user: &str, password: &str) -> String {
    let encoded = STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {encoded}")
}

fn read_hostname() -> String {
    // /etc/hostname is a one-liner on Linux/BSD. Empty on macOS/Windows is
    // fine — the ClickHouse schema defaults host_name to ''.
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}
