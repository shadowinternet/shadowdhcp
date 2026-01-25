use arc_swap::ArcSwap;

use dhcproto::{
    v6::{self, DhcpOption, DhcpOptions, RelayMessage},
    Decodable, Encodable,
};

use crate::config::Config;
use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;
use std::{
    fmt::Write,
    io,
    net::{SocketAddr, UdpSocket},
    sync::{mpsc, Arc},
    time::Duration,
};
use tracing::{debug, error, trace};

use crate::{
    analytics::events::{DhcpEvent, DhcpEventV6},
    v6::handlers::DhcpV6Response,
};

pub fn v6_worker(
    socket: UdpSocket,
    reservations: Arc<ArcSwap<ReservationDb>>,
    leases: Arc<LeaseDb>,
    config: Arc<ArcSwap<Config>>,
    event_channel: Option<mpsc::Sender<DhcpEvent>>,
) {
    let mut read_buf = [0u8; 2048];
    let mut error_count: u32 = 0;
    const MAX_BACKOFF_MS: u64 = 1000;

    // listen for messages
    loop {
        // if the src is not listening on response, it may send a ICMP host unreachable
        let (amount, src) = match socket.recv_from(&mut read_buf) {
            Ok((amount, src)) => {
                error_count = 0;
                debug!("Received {amount} bytes from {src:?}");
                trace!("Data: {}", hex_for_text2pcap(&read_buf[..amount]));
                (amount, src)
            }
            Err(err) => {
                match err.kind() {
                    io::ErrorKind::ConnectionReset => {
                        error!("Sent response to host that responded with ICMP unreachable");
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
        match v6::RelayMessage::from_bytes(&read_buf[..amount]) {
            Ok(msg) => {
                trace!("RelayMessage: {:#?}", msg);
                // get the inner msg from the option
                let inner_msg = match msg.opts().iter().find_map(|opt| match opt {
                    DhcpOption::RelayMsg(msg) => Some(msg),
                    _ => None,
                }) {
                    Some(msg) => match msg {
                        v6::RelayMessageData::Message(m) => m,
                        v6::RelayMessageData::Relay(_rm) => continue,
                    },
                    None => continue,
                };

                match crate::v6::handlers::handle_message(
                    &config.load(),
                    &reservations.load(),
                    &leases,
                    inner_msg,
                    &msg,
                ) {
                    DhcpV6Response::NoResponse(reason) => {
                        debug!("Not responding {:?}", reason);
                        if let Some(ref event_sender) = event_channel {
                            let relay_addr = match src {
                                SocketAddr::V6(v6) => *v6.ip(),
                                SocketAddr::V4(_) => continue, // DHCPv6 requires IPv6
                            };
                            let event =
                                DhcpEventV6::failed(inner_msg, &msg, relay_addr, reason.as_str());
                            let _ = event_sender.send(DhcpEvent::V6(event));
                        }
                    }
                    DhcpV6Response::Message(resp) => {
                        // wrap the message in a RelayRepl
                        let mut relay_reply_opts = DhcpOptions::new();
                        relay_reply_opts.insert(DhcpOption::RelayMsg(
                            v6::RelayMessageData::Message(resp.message),
                        ));

                        // reply with InterfaceId if it was included in the original RelayForw message
                        if let Some(interface_id) = msg
                            .opts
                            .iter()
                            .find(|opt| matches!(opt, v6::DhcpOption::InterfaceId(_)))
                        {
                            relay_reply_opts.insert(interface_id.clone());
                        }

                        let relay_msg = RelayMessage {
                            msg_type: v6::MessageType::RelayRepl,
                            hop_count: msg.hop_count(),
                            link_addr: msg.link_addr(),
                            peer_addr: msg.peer_addr(),
                            opts: relay_reply_opts,
                        };

                        let write_buf = match relay_msg.to_vec() {
                            Ok(buf) => buf,
                            Err(e) => {
                                error!("Failed to encode DHCPv6 response: {e}");
                                continue;
                            }
                        };
                        match socket.send_to(&write_buf, src) {
                            Ok(sent) => {
                                debug!("responded to {src} with {sent} bytes");
                                if let Some(ref event_sender) = event_channel {
                                    let relay_addr = match src {
                                        SocketAddr::V6(v6) => *v6.ip(),
                                        SocketAddr::V4(_) => continue, // DHCPv6 requires IPv6
                                    };
                                    let event = DhcpEventV6::success(
                                        inner_msg,
                                        &msg,
                                        relay_addr,
                                        resp.reservation.as_deref(),
                                        resp.reservation_match,
                                    );
                                    let _ = event_sender.send(DhcpEvent::V6(event));
                                }
                            }
                            Err(e) => error!("Problem sending response message: {e}"),
                        }
                    }
                }
            }
            Err(e) => {
                error!("Unable to parse dhcp message {}", e);
            }
        };
    }
}

fn hex_for_text2pcap(bytes: &[u8]) -> String {
    let mut s = String::new();
    s.push_str("0000 ");
    for b in bytes {
        write!(&mut s, " {:02x}", b).expect("writing to String");
    }
    s
}
