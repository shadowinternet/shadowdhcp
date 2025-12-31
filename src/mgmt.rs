use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::reservationdb::ReservationDb;
use shadow_dhcpv6::Reservation;

#[derive(Deserialize)]
#[serde(tag = "command")]
pub enum MgmtRequest {
    #[serde(rename = "reload")]
    Reload,
    #[serde(rename = "replace")]
    Replace { reservations: Vec<Reservation> },
    #[serde(rename = "status")]
    Status,
}

#[derive(Serialize)]
pub struct MgmtResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation_count: Option<usize>,
}

/// Main management listener loop
pub fn listener(
    listener: TcpListener,
    reservations: Arc<ArcSwap<ReservationDb>>,
    config_dir: PathBuf,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer = stream.peer_addr().ok();
                handle_client(stream, &reservations, &config_dir);
                if let Some(addr) = peer {
                    info!(%addr, "handled management request");
                }
            }
            Err(e) => {
                warn!(%e, "failed to accept management connection");
            }
        }
    }
}

fn handle_client(stream: TcpStream, reservations: &Arc<ArcSwap<ReservationDb>>, config_dir: &Path) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();

    match reader.read_line(&mut line) {
        Ok(0) => return, // EOF
        Ok(_) => {}
        Err(e) => {
            warn!(%e, "failed to read from management client");
            return;
        }
    }

    let response = match serde_json::from_str::<MgmtRequest>(&line) {
        Ok(MgmtRequest::Reload) => match reload_from_disk(reservations, config_dir) {
            Ok(count) => MgmtResponse {
                success: true,
                error: None,
                message: Some(format!("Reloaded {} reservations", count)),
                reservation_count: Some(count),
            },
            Err(e) => MgmtResponse {
                success: false,
                error: Some(e),
                message: None,
                reservation_count: None,
            },
        },
        Ok(MgmtRequest::Replace {
            reservations: new_res,
        }) => match atomic_write_reservations(config_dir, &new_res) {
            Ok(()) => {
                let count = new_res.len();
                let new_db = ReservationDb::new();
                new_db.load_reservations(new_res);
                reservations.store(Arc::new(new_db));
                info!(count, "replaced reservations via TCP and persisted to disk");
                MgmtResponse {
                    success: true,
                    error: None,
                    message: Some(format!("Replaced with {} reservations", count)),
                    reservation_count: Some(count),
                }
            }
            Err(e) => {
                warn!(%e, "failed to persist reservations to disk");
                MgmtResponse {
                    success: false,
                    error: Some(format!("Failed to write reservations: {}", e)),
                    message: None,
                    reservation_count: None,
                }
            }
        },
        Ok(MgmtRequest::Status) => {
            let db = reservations.load();
            let count = db.len();
            MgmtResponse {
                success: true,
                error: None,
                message: Some("Status OK".into()),
                reservation_count: Some(count),
            }
        }
        Err(e) => MgmtResponse {
            success: false,
            error: Some(format!("Invalid request: {}", e)),
            message: None,
            reservation_count: None,
        },
    };

    let mut writer = stream;
    if let Err(e) = serde_json::to_writer(&mut writer, &response) {
        warn!(%e, "failed to write response");
    }
    let _ = writer.write_all(b"\n");
}

/// Atomically write reservations to disk using write-rename pattern.
/// This ensures the file is never corrupted even if the process is killed mid-write.
fn atomic_write_reservations(
    config_dir: &Path,
    reservations: &[Reservation],
) -> std::io::Result<()> {
    use std::fs::{self, File};

    let target = config_dir.join("reservations.json");
    let temp = config_dir.join("reservations.json.tmp");

    // 1. Write to temp file (create truncates if exists)
    let mut file = File::create(&temp)?;
    serde_json::to_writer_pretty(&mut file, reservations).map_err(std::io::Error::other)?;
    file.write_all(b"\n")?;

    // 2. Flush to OS and sync to disk
    file.flush()?;
    file.sync_all()?;

    // 3. Atomic rename (overwrites target)
    fs::rename(&temp, &target)?;

    Ok(())
}

/// Load reservations from disk and swap into the running database
pub fn reload_from_disk(
    reservations: &Arc<ArcSwap<ReservationDb>>,
    config_dir: &Path,
) -> Result<usize, String> {
    let path = config_dir.join("reservations.json");
    let file = std::fs::File::open(&path)
        .map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;

    let new_reservations: Vec<Reservation> = serde_json::from_reader(file)
        .map_err(|e| format!("Failed to parse reservations: {}", e))?;

    let count = new_reservations.len();
    let new_db = ReservationDb::new();
    new_db.load_reservations(new_reservations);
    reservations.store(Arc::new(new_db));

    info!(count, "reloaded reservations from disk");
    Ok(count)
}
