use std::io::IsTerminal;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer, Registry,
};

use crate::config::{FileLogConfig, LoggingConfig};

type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;

/// Background worker guards returned to the caller, who holds them until the
/// end of `main` — dropping them flushes and shuts down the writer threads.
pub struct LogGuards {
    _stdout_worker: Option<WorkerGuard>,
    _file_worker: Option<WorkerGuard>,
}

/// Install the tracing subscriber with the sinks described in `cfg` and
/// return the guards the caller must keep alive until exit.
///
/// If no sink resolves to enabled, falls back to stdout so the process isn't
/// silently deaf.
pub fn init(cfg: &LoggingConfig) -> LogGuards {
    let filter = LevelFilter::from_level(cfg.level);

    let mut layers: Vec<BoxedLayer> = Vec::new();
    let mut stdout_guard: Option<WorkerGuard> = None;
    let mut file_guard: Option<WorkerGuard> = None;

    if cfg.stdout {
        let (layer, guard) = stdout_layer(filter);
        layers.push(layer);
        stdout_guard = Some(guard);
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

    if layers.is_empty() {
        eprintln!("logging: no sinks enabled in `logging` block; falling back to stdout");
        let (layer, guard) = stdout_layer(filter);
        layers.push(layer);
        stdout_guard = Some(guard);
    }

    tracing_subscriber::registry().with(layers).init();

    LogGuards {
        _stdout_worker: stdout_guard,
        _file_worker: file_guard,
    }
}

/// TTY-aware stdout layer: pretty when attached to a terminal, JSON when piped.
///
/// The writer is non-blocking (and lossy past its buffer) so a stalled pipe —
/// `| less` left paged, a dead supervisor — can't freeze DHCP responses.
fn stdout_layer(filter: LevelFilter) -> (BoxedLayer, WorkerGuard) {
    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
    let layer = if std::io::stdout().is_terminal() {
        fmt::layer()
            .with_writer(writer)
            .with_target(true)
            .with_thread_names(true)
            .with_filter(filter)
            .boxed()
    } else {
        fmt::layer()
            .json()
            .with_writer(writer)
            .with_target(true)
            .with_thread_names(true)
            .with_filter(filter)
            .boxed()
    };
    (layer, guard)
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
        .with_filter(filter)
        .boxed();
    Ok((layer, guard))
}
