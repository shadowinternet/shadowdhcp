use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;
use tracing::{error, info};

use crate::mgmt;
use crate::reservationdb::ReservationDb;

/// Spawn a thread that handles SIGHUP by reloading reservations from disk
pub fn spawn_sighup_handler(
    reservations: Arc<ArcSwap<ReservationDb>>,
    config_dir: PathBuf,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("sighup".to_string())
        .spawn(move || {
            let mut signals =
                Signals::new([SIGHUP]).expect("Failed to register SIGHUP handler");

            for sig in signals.forever() {
                if sig == SIGHUP {
                    info!("received SIGHUP, reloading reservations");
                    match mgmt::reload_from_disk(&reservations, &config_dir) {
                        Ok(count) => info!(count, "reloaded reservations"),
                        Err(e) => error!(%e, "failed to reload reservations"),
                    }
                }
            }
        })
        .expect("Failed to spawn SIGHUP handler thread")
}
