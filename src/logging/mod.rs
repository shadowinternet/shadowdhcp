use std::io::IsTerminal;
use std::sync::OnceLock;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer, Registry,
};

#[cfg(feature = "clickhouse")]
pub mod clickhouse;

use crate::config::{ClickHouseConfig, FileLogConfig, LoggingConfig};

type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;

/// Background worker guards kept alive for the process lifetime — dropping
/// them would shut down the writer threads.
static GUARDS: OnceLock<Guards> = OnceLock::new();

#[allow(dead_code)]
struct Guards {
    file_worker: Option<WorkerGuard>,
}

/// Background closure the caller spawns after `init` returns. Today this is
/// just the ClickHouse writer; the file appender's `WorkerGuard` is parked in
/// `GUARDS` and stdout runs synchronously in the tracing pipeline. `Option`
/// is `Some` only when the ClickHouse sink is enabled.
pub type LogWriterTask = Box<dyn FnOnce() + Send + 'static>;

/// Install the tracing subscriber with the sinks described in `cfg` and
/// return the ClickHouse writer task (when the feature is on and the sink is
/// configured) for the caller to spawn. Without spawning it, the layer's
/// bounded channel will fill and rows will be dropped.
///
/// If no sink resolves to enabled, falls back to stdout so the process isn't
/// silently deaf.
pub fn init(
    cfg: &LoggingConfig,
    clickhouse_cfg: Option<&ClickHouseConfig>,
) -> Option<LogWriterTask> {
    let filter = LevelFilter::from_level(cfg.level);

    let mut layers: Vec<BoxedLayer> = Vec::new();
    let mut file_guard: Option<WorkerGuard> = None;

    if cfg.stdout {
        layers.push(stdout_layer(filter));
    }

    if let Some(file_cfg) = cfg.file.as_ref() {
        match build_file_layer(file_cfg, filter) {
            Ok((layer, guard)) => {
                layers.push(layer);
                file_guard = Some(guard);
            }
            Err(e) => {
                eprintln!(
                    "logging: failed to open file sink at {}: {e} — continuing without file logging",
                    file_cfg.path.display()
                );
            }
        }
    }

    #[cfg(feature = "clickhouse")]
    let log_writer: Option<LogWriterTask> =
        clickhouse_cfg.filter(|_| cfg.clickhouse).map(|ch_cfg| {
            let (layer, task) = clickhouse::build(ch_cfg.clone(), filter, cfg.queue_size);
            layers.push(layer);
            Box::new(task) as LogWriterTask
        });
    #[cfg(not(feature = "clickhouse"))]
    let log_writer: Option<LogWriterTask> = {
        let _ = clickhouse_cfg;
        None
    };

    if layers.is_empty() {
        eprintln!("logging: no sinks enabled in `logging` block; falling back to stdout");
        layers.push(stdout_layer(filter));
    }

    tracing_subscriber::registry().with(layers).init();

    let _ = GUARDS.set(Guards {
        file_worker: file_guard,
    });

    log_writer
}

/// TTY-aware stdout layer: pretty when attached to a terminal, JSON when piped.
fn stdout_layer(filter: LevelFilter) -> BoxedLayer {
    if std::io::stdout().is_terminal() {
        fmt::layer()
            .with_writer(std::io::stdout)
            .with_target(true)
            .with_thread_names(true)
            .with_filter(filter)
            .boxed()
    } else {
        fmt::layer()
            .json()
            .with_writer(std::io::stdout)
            .with_target(true)
            .with_thread_names(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_filter(filter)
            .boxed()
    }
}

fn build_file_layer(
    cfg: &FileLogConfig,
    filter: LevelFilter,
) -> std::io::Result<(BoxedLayer, WorkerGuard)> {
    let dir = cfg
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let file_name = cfg
        .path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing filename"))?;

    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(file_name.to_string_lossy().as_ref())
        .max_log_files(cfg.max_files)
        .build(dir)
        .map_err(std::io::Error::other)?;

    let (writer, guard) = tracing_appender::non_blocking(appender);
    let layer = fmt::layer()
        .json()
        .with_writer(writer)
        .with_target(true)
        .with_thread_names(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_filter(filter)
        .boxed();
    Ok((layer, guard))
}
