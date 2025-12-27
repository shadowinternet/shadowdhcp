use arc_swap::ArcSwap;
use dhcproto::{v4, Decodable, Encodable};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::{mpsc, Arc},
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
    reservations: Arc<ArcSwap<ReservationDb>>,
    leases: Arc<LeaseDb>,
    config: Arc<ArcSwap<Config>>,
    event_channel: Option<mpsc::Sender<DhcpEvent>>,
) {
    let mut read_buf = [0u8; 2048];
    let bind_addr = config.load().v4_bind_address;
    let socket = UdpSocket::bind(bind_addr).expect("udp bind");
    info!("Successfully bound to: {bind_addr}");

    loop {
        let (amount, src) = match socket.recv_from(&mut read_buf) {
            Ok((amount, src)) => {
                debug!("Received {amount} bytes from {src:?}");
                trace!("Data: {:x?}", &read_buf[..amount]);
                (amount, src)
            }
            Err(err) => {
                error!("Error receiving: {err:?}");
                match err.kind() {
                    io::ErrorKind::ConnectionReset => {
                        info!("Sent response to host that responded with ICMP unreachable");
                        continue;
                    }
                    _ => todo!(),
                }
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
                    let write_buf = resp.message.to_vec().expect("encoding response message");
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
