use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use tracing::{error, info};

use crate::mgmt;
use crate::reservationdb::ReservationDb;
use crate::shutdown::Shutdown;

/// Spawn a thread that handles SIGHUP by reloading reservations from disk,
/// and SIGTERM/SIGINT by signalling shutdown so every worker and writer
/// thread drains and exits (letting `main` return and flush log buffers).
pub fn spawn_signal_handler(
    reservations: Arc<ArcSwap<ReservationDb>>,
    config_dir: PathBuf,
    shutdown: Shutdown,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("signals".to_string())
        .spawn(move || {
            let mut signals =
                Signals::new([SIGHUP, SIGTERM, SIGINT]).expect("Failed to register signal handler");

            for sig in signals.forever() {
                match sig {
                    SIGHUP => {
                        info!("received SIGHUP, reloading reservations");
                        match mgmt::reload_from_disk(&reservations, &config_dir) {
                            Ok(count) => info!(count, "reloaded reservations"),
                            Err(e) => error!(%e, "failed to reload reservations"),
                        }
                    }
                    SIGTERM | SIGINT => {
                        info!(signal = sig, "received shutdown signal, draining");
                        shutdown.signal();
                        return;
                    }
                    _ => {}
                }
            }
        })
        .expect("Failed to spawn signal handler thread")
}
