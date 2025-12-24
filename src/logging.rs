use std::io::IsTerminal;
use tracing::Level;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer};

/// Initialize tracing subscriber.
/// Automatically selects JSON output when stdout is not a terminal (piped to another program).
pub fn init_stdout(max_level: Level) {
    let filter = tracing_subscriber::filter::LevelFilter::from_level(max_level);

    if std::io::stdout().is_terminal() {
        // Human-readable output for interactive use
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_writer(std::io::stdout)
                    .with_target(true)
                    .with_thread_names(true)
                    .with_filter(filter),
            )
            .init();
    } else {
        // JSON output for machine consumption (Vector, etc.)
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .json()
                    .with_writer(std::io::stdout)
                    .with_target(true)
                    .with_thread_names(true)
                    .with_current_span(true)
                    .with_span_list(true)
                    .with_filter(filter),
            )
            .init();
    }
}
