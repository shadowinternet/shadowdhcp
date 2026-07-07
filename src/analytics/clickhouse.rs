use serde::Serialize;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use ureq::Agent;

use crate::analytics::batch::{run, BatchConfig, BatchSink};
use crate::analytics::clickhouse_http::{
    basic_auth_header, build_agent, post, read_hostname, PostOutcome,
};
use crate::analytics::events::{DhcpEvent, DhcpEventV6};
use crate::config::ClickHouseConfig;
use crate::shutdown::Shutdown;

const MAX_BATCH: usize = 2048;
const MAX_BATCH_LATENCY: Duration = Duration::from_secs(3);
const RETRY_SLEEP: Duration = Duration::from_secs(3);
/// Sized so that `MAX_RETRIES * RETRY_SLEEP` (~5–6 min with jitter) covers
/// short ClickHouse maintenance windows without dropping the in-flight batch.
const MAX_RETRIES: u32 = 100;

/// Row shape sent to ClickHouse: event fields plus the server hostname.
/// `ip_version` from the enum tag is intentionally dropped — the destination
/// table is already known from the INSERT URL.
#[derive(Serialize)]
struct HostRow<'a, T: Serialize> {
    host_name: &'a str,
    #[serde(flatten)]
    inner: &'a T,
}

/// V6 row wrapper that splits `Ipv6Net` PD fields into separate prefix/length
/// columns to match the ClickHouse schema. The original `requested_ipv6_pd`
/// and `reservation_ipv6_pd` fields still appear in the JSON via the flatten;
/// ClickHouse drops them because the URL sets `input_format_skip_unknown_fields=1`.
#[derive(Serialize)]
struct V6Row<'a> {
    host_name: &'a str,
    requested_ipv6_pd_prefix: Option<Ipv6Addr>,
    requested_ipv6_pd_length: Option<u8>,
    reservation_ipv6_pd_prefix: Option<Ipv6Addr>,
    reservation_ipv6_pd_length: Option<u8>,
    #[serde(flatten)]
    inner: &'a DhcpEventV6,
}

struct ChEventsSink {
    agent: Agent,
    base_url: String,
    url_v4: String,
    url_v6: String,
    auth: String,
    host_name: String,
    body_v4: Vec<u8>,
    body_v6: Vec<u8>,
    count_v4: usize,
    count_v6: usize,
    dropped: Arc<AtomicU64>,
}

impl BatchSink<DhcpEvent> for ChEventsSink {
    fn reset(&mut self) {
        self.body_v4.clear();
        self.body_v6.clear();
        self.count_v4 = 0;
        self.count_v6 = 0;
    }

    fn push(&mut self, event: DhcpEvent) {
        match event {
            DhcpEvent::V4(v4) => {
                let row = HostRow {
                    host_name: &self.host_name,
                    inner: &v4,
                };
                if serde_json::to_writer(&mut self.body_v4, &row).is_ok() {
                    self.body_v4.push(b'\n');
                    self.count_v4 += 1;
                }
            }
            DhcpEvent::V6(v6) => {
                let row = V6Row {
                    host_name: &self.host_name,
                    requested_ipv6_pd_prefix: v6.requested_ipv6_pd.map(|n| n.network()),
                    requested_ipv6_pd_length: v6.requested_ipv6_pd.map(|n| n.prefix_len()),
                    reservation_ipv6_pd_prefix: v6.reservation_ipv6_pd.map(|n| n.network()),
                    reservation_ipv6_pd_length: v6.reservation_ipv6_pd.map(|n| n.prefix_len()),
                    inner: &v6,
                };
                if serde_json::to_writer(&mut self.body_v6, &row).is_ok() {
                    self.body_v6.push(b'\n');
                    self.count_v6 += 1;
                }
            }
        }
    }

    fn item_count(&self) -> usize {
        self.count_v4 + self.count_v6
    }

    /// POST v4 then v6.
    ///
    /// Per-sub-batch outcome:
    /// * `Ok` — clear the buffer.
    /// * `Permanent` (4xx other than 408/429) — drop the sub-batch with a warn
    ///   so a single poisoned row can't wedge the writer forever. Don't
    ///   propagate; the other sub-batch may still be transient.
    /// * `Transient` (5xx, network, 408/429) — leave the sub-batch buffered so
    ///   the runner retries it.
    ///
    /// Returns `Err` only if any sub-batch was transient.
    fn flush(&mut self) -> Result<(), ()> {
        let mut overall = Ok(());
        if self.count_v4 > 0 {
            match post(&self.agent, &self.url_v4, &self.auth, &self.body_v4) {
                PostOutcome::Ok => {
                    self.body_v4.clear();
                    self.count_v4 = 0;
                }
                PostOutcome::Permanent(status) => {
                    warn!(
                        "ClickHouse v4 dropped batch of {} after permanent HTTP {status}",
                        self.count_v4
                    );
                    self.body_v4.clear();
                    self.count_v4 = 0;
                }
                PostOutcome::Transient(msg) => {
                    warn!("ClickHouse v4 batch of {} retrying: {msg}", self.count_v4);
                    overall = Err(());
                }
            }
        }
        if self.count_v6 > 0 {
            match post(&self.agent, &self.url_v6, &self.auth, &self.body_v6) {
                PostOutcome::Ok => {
                    self.body_v6.clear();
                    self.count_v6 = 0;
                }
                PostOutcome::Permanent(status) => {
                    warn!(
                        "ClickHouse v6 dropped batch of {} after permanent HTTP {status}",
                        self.count_v6
                    );
                    self.body_v6.clear();
                    self.count_v6 = 0;
                }
                PostOutcome::Transient(msg) => {
                    warn!("ClickHouse v6 batch of {} retrying: {msg}", self.count_v6);
                    overall = Err(());
                }
            }
        }
        overall
    }

    fn on_start(&mut self) {
        info!(
            "Starting ClickHouse writer -> {} (host_name={:?})",
            self.base_url, self.host_name
        );
    }

    fn on_cycle_complete(&mut self) {
        let n = self.dropped.swap(0, Ordering::Relaxed);
        if n > 0 {
            warn!("Dropped {n} DHCP events at sender (channel full)");
        }
    }

    fn on_giveup(&mut self) {
        let total = self.count_v4 + self.count_v6;
        if total > 0 {
            warn!("ClickHouse dropped batch of {total} after exhausted retries");
        }
    }
}

pub fn clickhouse_writer(
    cfg: ClickHouseConfig,
    rx: mpsc::Receiver<DhcpEvent>,
    dropped: Arc<AtomicU64>,
    shutdown: Shutdown,
) {
    let base_url = cfg.url.trim_end_matches('/').to_string();
    // input_format_skip_unknown_fields lets us emit JSON keys that aren't in
    // the schema (e.g. the original `requested_ipv6_pd` Ipv6Net string that
    // we replace with split prefix/length columns) without ClickHouse rejecting
    // the batch.
    let url_v4 = format!(
        "{base_url}/?database={db}&input_format_skip_unknown_fields=1&query=INSERT+INTO+events_v4+FORMAT+JSONEachRow",
        db = cfg.database,
    );
    let url_v6 = format!(
        "{base_url}/?database={db}&input_format_skip_unknown_fields=1&query=INSERT+INTO+events_v6+FORMAT+JSONEachRow",
        db = cfg.database,
    );

    let mut sink = ChEventsSink {
        agent: build_agent(),
        base_url,
        url_v4,
        url_v6,
        auth: basic_auth_header(&cfg.user, &cfg.password),
        host_name: cfg.hostname.unwrap_or_else(read_hostname),
        body_v4: Vec::with_capacity(512 * 1024),
        body_v6: Vec::with_capacity(512 * 1024),
        count_v4: 0,
        count_v6: 0,
        dropped,
    };

    run(
        rx,
        &mut sink,
        BatchConfig {
            max_batch: MAX_BATCH,
            max_latency: MAX_BATCH_LATENCY,
            retry_sleep: RETRY_SLEEP,
            max_retries: MAX_RETRIES,
        },
        &shutdown,
    );
}
