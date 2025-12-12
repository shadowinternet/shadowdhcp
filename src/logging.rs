use tracing::Level;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer};

pub fn init_stdout(max_level: Level) {
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(std::io::stdout)
                .with_target(true)
                .with_thread_names(true)
                .with_filter(tracing_subscriber::filter::LevelFilter::from_level(
                    max_level,
                )),
        )
        .init();
}
