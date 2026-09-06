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

/// The buffered rows bound for one table. Each event variant has its own,
/// since each lands in a different table and is POSTed separately.
struct SubBatch {
    table: &'static str,
    url: String,
    body: Vec<u8>,
    count: usize,
}

impl SubBatch {
    /// `capacity` is the initial body buffer. It is only ever cleared, never
    /// shrunk, so size it for the table's real volume.
    fn new(base_url: &str, database: &str, table: &'static str, capacity: usize) -> Self {
        // input_format_skip_unknown_fields lets us emit JSON keys that aren't
        // in the schema (e.g. the original `requested_ipv6_pd` Ipv6Net string
        // that we replace with split prefix/length columns) without ClickHouse
        // rejecting the batch.
        let url = format!(
            "{base_url}/?database={database}&input_format_skip_unknown_fields=1\
             &query=INSERT+INTO+{table}+FORMAT+JSONEachRow"
        );
        Self {
            table,
            url,
            body: Vec::with_capacity(capacity),
            count: 0,
        }
    }

    fn push<T: Serialize>(&mut self, row: &T) {
        if serde_json::to_writer(&mut self.body, row).is_ok() {
            self.body.push(b'\n');
            self.count += 1;
        }
    }

    fn clear(&mut self) {
        self.body.clear();
        self.count = 0;
    }

    /// POST this sub-batch.
    ///
    /// * `Ok` - clear the buffer.
    /// * `Permanent` (4xx other than 408/429) - drop the sub-batch with a warn
    ///   so a single poisoned row can't wedge the writer forever.
    /// * `Transient` (5xx, network, 408/429) - leave it buffered and return
    ///   `Err` so the runner retries it.
    fn flush(&mut self, agent: &Agent, auth: &str) -> Result<(), ()> {
        if self.count == 0 {
            return Ok(());
        }
        match post(agent, &self.url, auth, &self.body) {
            PostOutcome::Ok => {
                self.clear();
                Ok(())
            }
            PostOutcome::Permanent(status) => {
                warn!(
                    "ClickHouse {} dropped batch of {} after permanent HTTP {status}",
                    self.table, self.count
                );
                self.clear();
                Ok(())
            }
            PostOutcome::Transient(msg) => {
                warn!(
                    "ClickHouse {} batch of {} retrying: {msg}",
                    self.table, self.count
                );
                Err(())
            }
        }
    }
}

struct ChEventsSink {
    agent: Agent,
    base_url: String,
    auth: String,
    host_name: String,
    v4: SubBatch,
    v6: SubBatch,
    dropped: Arc<AtomicU64>,
}

impl BatchSink<DhcpEvent> for ChEventsSink {
    fn reset(&mut self) {
        self.v4.clear();
        self.v6.clear();
    }

    fn push(&mut self, event: DhcpEvent) {
        let host_name = self.host_name.as_str();
        match event {
            DhcpEvent::V4(v4) => self.v4.push(&HostRow {
                host_name,
                inner: &v4,
            }),
            DhcpEvent::V6(v6) => self.v6.push(&V6Row {
                host_name,
                requested_ipv6_pd_prefix: v6.requested_ipv6_pd.map(|n| n.network()),
                requested_ipv6_pd_length: v6.requested_ipv6_pd.map(|n| n.prefix_len()),
                reservation_ipv6_pd_prefix: v6.reservation_ipv6_pd.map(|n| n.network()),
                reservation_ipv6_pd_length: v6.reservation_ipv6_pd.map(|n| n.prefix_len()),
                inner: &v6,
            }),
        }
    }

    fn item_count(&self) -> usize {
        self.v4.count + self.v6.count
    }

    /// POST v4 then v6. A permanent failure on one does not stop the other;
    /// returns `Err` if either was transient.
    fn flush(&mut self) -> Result<(), ()> {
        let v4 = self.v4.flush(&self.agent, &self.auth);
        let v6 = self.v6.flush(&self.agent, &self.auth);
        v4.and(v6)
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
        let total = self.item_count();
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

    let mut sink = ChEventsSink {
        agent: build_agent(),
        v4: SubBatch::new(&base_url, &cfg.database, "events_v4", 512 * 1024),
        v6: SubBatch::new(&base_url, &cfg.database, "events_v6", 512 * 1024),
        base_url,
        auth: basic_auth_header(&cfg.user, &cfg.password),
        host_name: cfg.hostname.unwrap_or_else(read_hostname),
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
