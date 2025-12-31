use arc_swap::ArcSwap;
use dhcproto::{v4, Decodable, Encodable};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::{mpsc, Arc},
    time::Duration,
};
use tracing::{debug, error, info, trace};

use crate::config::Config;
use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;

use crate::{
    analytics::events::{DhcpEvent, DhcpEventV4},
    v4::handlers::{handle_message, DhcpV4Response},
};

pub fn v4_worker(
    socket: UdpSocket,
    reservations: Arc<ArcSwap<ReservationDb>>,
    leases: Arc<LeaseDb>,
    config: Arc<ArcSwap<Config>>,
    event_channel: Option<mpsc::Sender<DhcpEvent>>,
) {
    let mut read_buf = [0u8; 2048];
    let mut error_count: u32 = 0;
    const MAX_BACKOFF_MS: u64 = 1000;

    loop {
        let (amount, src) = match socket.recv_from(&mut read_buf) {
            Ok((amount, src)) => {
                error_count = 0;
                debug!("Received {amount} bytes from {src:?}");
                trace!("Data: {:x?}", &read_buf[..amount]);
                (amount, src)
            }
            Err(err) => {
                match err.kind() {
                    io::ErrorKind::ConnectionReset => {
                        info!("Sent response to host that responded with ICMP unreachable");
                    }
                    io::ErrorKind::Interrupted => {
                        debug!("recv_from interrupted, retrying");
                    }
                    _ => {
                        error!("Unexpected socket error: {err:?}");
                        // Apply exponential backoff to prevent CPU spin on persistent errors
                        error_count = error_count.saturating_add(1);
                        let backoff_ms = std::cmp::min(
                            10_u64.saturating_mul(2_u64.saturating_pow(error_count)),
                            MAX_BACKOFF_MS,
                        );
                        std::thread::sleep(Duration::from_millis(backoff_ms));
                    }
                }
                continue;
            }
        };

        match v4::Message::from_bytes(&read_buf[..amount]) {
            Ok(msg) => match handle_message(&reservations.load(), &leases, &config.load(), &msg) {
                DhcpV4Response::NoResponse(reason) => {
                    debug!("Not responding {:?}", reason);
                    if let Some(ref event_sender) = event_channel {
                        let relay_addr = match src {
                            SocketAddr::V4(v4) => *v4.ip(),
                            SocketAddr::V6(_) => continue,
                        };
                        let event = DhcpEventV4::failed(&msg, relay_addr, reason.as_str());
                        let _ = event_sender.send(DhcpEvent::V4(event));
                    }
                }
                DhcpV4Response::Message(resp) => {
                    let write_buf = match resp.message.to_vec() {
                        Ok(buf) => buf,
                        Err(e) => {
                            error!("Failed to encode DHCPv4 response: {e}");
                            continue;
                        }
                    };
                    match socket.send_to(&write_buf, src) {
                        Ok(sent) => {
                            debug!("responded to {src} with {sent} bytes");
                            if let Some(ref event_sender) = event_channel {
                                let relay_addr = match src {
                                    SocketAddr::V4(v4) => *v4.ip(),
                                    SocketAddr::V6(_) => continue,
                                };
                                let event = DhcpEventV4::success(
                                    &msg,
                                    relay_addr,
                                    resp.reservation.as_deref(),
                                    resp.reservation_match,
                                );
                                let _ = event_sender.send(DhcpEvent::V4(event));
                            }
                        }
                        Err(e) => error!("Problem sending response message: {e}"),
                    }
                }
            },
            Err(e) => {
                error!("Unable to parse dhcpv4 message {}", e);
            }
        }
    }
}
