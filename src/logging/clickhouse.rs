use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;
use ureq::Agent;

use crate::batch::{run, BatchConfig, BatchSink};
use crate::clickhouse_http::{basic_auth_header, build_agent, post, read_hostname, PostOutcome};
use crate::config::ClickHouseConfig;

const SERVICE_NAME: &str = "shadowdhcp";
const SCOPE_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_BATCH: usize = 2048;
const MAX_BATCH_LATENCY: Duration = Duration::from_secs(3);
const RETRY_SLEEP: Duration = Duration::from_secs(3);
/// Sized so that `MAX_RETRIES * RETRY_SLEEP` (~5–6 min with jitter) covers
/// short ClickHouse maintenance windows without dropping the in-flight batch.
const MAX_RETRIES: u32 = 100;

/// One captured log row, enqueued to the writer thread.
struct LogRow {
    /// Nanoseconds since the Unix epoch. Sent to ClickHouse as a JSON integer
    /// so DateTime64(9) parses the raw tick count regardless of the server's
    /// `date_time_input_format` setting.
    timestamp_nanos: u64,
    level: tracing::Level,
    body: String,
    log_attrs: BTreeMap<String, String>,
}

pub struct ClickHouseLogLayer {
    tx: mpsc::SyncSender<LogRow>,
    filter: LevelFilter,
    /// Producer-side drop counter shared with the writer thread. Incremented
    /// when `try_send` fails because the bounded channel is full; the writer
    /// reads and resets it once per flush cycle.
    dropped: Arc<AtomicU64>,
}

/// Build the layer and a closure that drains its channel into ClickHouse. The
/// caller spawns the closure on its own thread; without that, the bounded
/// channel will fill and rows will be dropped.
pub fn build(
    cfg: ClickHouseConfig,
    filter: LevelFilter,
    queue_size: usize,
) -> (super::BoxedLayer, impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::sync_channel::<LogRow>(queue_size);
    let dropped = Arc::new(AtomicU64::new(0));
    let layer = Box::new(ClickHouseLogLayer {
        tx,
        filter,
        dropped: dropped.clone(),
    });
    let task = move || writer(cfg, rx, dropped);
    (layer, task)
}

/// Per-span field bag, kept in span extensions so descendant events can pull
/// `mac` / `xid` / `client_id` etc into their own log row.
struct SpanFields(BTreeMap<String, String>);

impl<S> Layer<S> for ClickHouseLogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut visitor = Visitor::for_span();
        attrs.record(&mut visitor);
        span.extensions_mut().insert(SpanFields(visitor.fields));
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        let Some(SpanFields(fields)) = ext.get_mut::<SpanFields>() else {
            return;
        };
        let mut visitor = Visitor::for_span();
        values.record(&mut visitor);
        fields.extend(visitor.fields);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // Per-layer level filter — applied here because we don't go through a
        // `with_filter` wrapper (which would prevent on_new_span/on_record
        // span context bookkeeping for events outside the filter).
        if let Some(max) = self.filter.into_level() {
            if *event.metadata().level() > max {
                return;
            }
        }

        let metadata = event.metadata();
        let mut visitor = Visitor::for_event();
        event.record(&mut visitor);

        // Walk every enclosing span and merge their captured fields. Closer
        // spans win on key conflicts (insert overwrites), and event fields in
        // turn override span fields.
        let mut log_attrs: BTreeMap<String, String> = BTreeMap::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if let Some(SpanFields(fields)) = span.extensions().get::<SpanFields>() {
                    log_attrs.extend(fields.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
            }
        }
        log_attrs.extend(visitor.fields);
        log_attrs.insert("target".into(), metadata.target().to_string());

        let row = LogRow {
            timestamp_nanos: now_nanos(),
            level: *metadata.level(),
            body: visitor.message,
            log_attrs,
        };
        if self.tx.try_send(row).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn severity_of(level: tracing::Level) -> (u8, &'static str) {
    match level {
        tracing::Level::TRACE => (1, "TRACE"),
        tracing::Level::DEBUG => (5, "DEBUG"),
        tracing::Level::INFO => (9, "INFO"),
        tracing::Level::WARN => (13, "WARN"),
        tracing::Level::ERROR => (17, "ERROR"),
    }
}

/// Tracing field visitor used for both spans and events. For events the
/// special `message` field accumulates into `message`; for spans every field
/// (including any literal `message`) lands in `fields`.
#[derive(Default)]
struct Visitor {
    extract_message: bool,
    message: String,
    fields: BTreeMap<String, String>,
}

impl Visitor {
    fn for_span() -> Self {
        Self::default()
    }

    fn for_event() -> Self {
        Self {
            extract_message: true,
            ..Self::default()
        }
    }

    fn push(&mut self, name: &str, value: String) {
        self.fields.insert(name.to_string(), value);
    }
}

impl Visit for Visitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if self.extract_message && field.name() == "message" {
            let _ = write!(&mut self.message, "{value:?}");
        } else {
            self.push(field.name(), format!("{value:?}"));
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if self.extract_message && field.name() == "message" {
            self.message.push_str(value);
        } else {
            self.push(field.name(), value.to_string());
        }
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field.name(), value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field.name(), value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field.name(), value.to_string());
    }
}

// =============================================================================
// Writer thread: batches LogRows and POSTs them as JSONEachRow inserts.
// All diagnostics use eprintln! to avoid a feedback loop through tracing.
// =============================================================================

struct ChLogsSink {
    agent: Agent,
    base_url: String,
    url: String,
    auth: String,
    host_name: String,
    body: Vec<u8>,
    count: usize,
    dropped: Arc<AtomicU64>,
}

impl BatchSink<LogRow> for ChLogsSink {
    fn reset(&mut self) {
        self.body.clear();
        self.count = 0;
    }

    fn push(&mut self, row: LogRow) {
        let (severity_number, severity_text) = severity_of(row.level);
        let payload = json!({
            "Timestamp": row.timestamp_nanos,
            "TraceId": "",
            "SpanId": "",
            "TraceFlags": 0,
            "SeverityText": severity_text,
            "SeverityNumber": severity_number,
            "ServiceName": SERVICE_NAME,
            "Body": row.body,
            "ResourceSchemaUrl": "",
            "ResourceAttributes": {
                "service.name": SERVICE_NAME,
                "host.name": &self.host_name,
            },
            "ScopeSchemaUrl": "",
            "ScopeName": SERVICE_NAME,
            "ScopeVersion": SCOPE_VERSION,
            "ScopeAttributes": {},
            "LogAttributes": row.log_attrs,
        });
        if serde_json::to_writer(&mut self.body, &payload).is_ok() {
            self.body.push(b'\n');
            self.count += 1;
        }
    }

    fn item_count(&self) -> usize {
        self.count
    }

    /// Same permanent-vs-transient split as the events writer: drop on 4xx
    /// (other than 408/429), retry on 5xx / network. Diagnostics use
    /// `eprintln!` to avoid a feedback loop through tracing.
    fn flush(&mut self) -> Result<(), ()> {
        if self.count == 0 {
            return Ok(());
        }
        match post(&self.agent, &self.url, &self.auth, &self.body) {
            PostOutcome::Ok => Ok(()),
            PostOutcome::Permanent(status) => {
                eprintln!(
                    "ch-logs: dropped batch of {} after permanent HTTP {status}",
                    self.count
                );
                self.body.clear();
                self.count = 0;
                Ok(())
            }
            PostOutcome::Transient(msg) => {
                eprintln!("ch-logs: batch of {} retrying: {msg}", self.count);
                Err(())
            }
        }
    }

    fn on_start(&mut self) {
        eprintln!(
            "ch-logs: starting writer -> {} (host_name={:?})",
            self.base_url, self.host_name
        );
    }

    fn on_cycle_complete(&mut self) {
        let n = self.dropped.swap(0, Ordering::Relaxed);
        if n > 0 {
            eprintln!("ch-logs: dropped {n} log rows at sender (channel full)");
        }
    }

    fn on_giveup(&mut self) {
        if self.count > 0 {
            eprintln!(
                "ch-logs: dropped batch of {} after exhausted retries",
                self.count
            );
        }
    }
}

fn writer(cfg: ClickHouseConfig, rx: mpsc::Receiver<LogRow>, dropped: Arc<AtomicU64>) {
    let base_url = cfg.url.trim_end_matches('/').to_string();
    let url = format!(
        "{base_url}/?database={db}&query=INSERT+INTO+otel_logs+FORMAT+JSONEachRow",
        db = cfg.database,
    );

    let mut sink = ChLogsSink {
        agent: build_agent(),
        base_url,
        url,
        auth: basic_auth_header(&cfg.user, &cfg.password),
        host_name: cfg.hostname.unwrap_or_else(read_hostname),
        body: Vec::with_capacity(64 * 1024),
        count: 0,
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
    );
}
