use arc_swap::ArcSwap;

use dhcproto::{
    v6::{self, DhcpOption, DhcpOptions, RelayMessage},
    Decodable, Encodable,
};

use crate::config::Config;
use crate::opt82_cache::Opt82Cache;
use crate::reservationdb::ReservationDb;
use crate::shutdown::Shutdown;
use std::{
    fmt::Write,
    io,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, error, info, trace};

use crate::{
    analytics::{
        events::{DhcpEvent, DhcpEventV6},
        EventSenders,
    },
    types::Duid,
    v6::extensions::{ShadowMessageExtV6, ShadowRelayMessageExtV6},
    v6::handlers::{DhcpV6Response, NoResponse},
};

pub fn v6_worker(
    socket: UdpSocket,
    reservations: Arc<ArcSwap<ReservationDb>>,
    leases: Arc<Opt82Cache>,
    config: Arc<ArcSwap<Config>>,
    event_channel: Option<EventSenders>,
    shutdown: Shutdown,
) {
    let mut read_buf = [0u8; 2048];
    let mut error_count: u32 = 0;
    const MAX_BACKOFF_MS: u64 = 1000;

    // Wake once per second so the shutdown flag is noticed promptly.
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set v6 socket read timeout");

    // listen for messages
    loop {
        if shutdown.is_signalled() {
            info!("v6 worker shutting down");
            return;
        }
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
                    // Read-timeout expiry: WouldBlock on Unix, TimedOut on Windows
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {}
                    io::ErrorKind::ConnectionReset => {
                        debug!("Sent response to host that responded with ICMP unreachable");
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

        let relay_addr = match src {
            SocketAddr::V6(v6) => Some(*v6.ip()),
            SocketAddr::V4(_) => None,
        };

        match v6::RelayMessage::from_bytes(&read_buf[..amount]) {
            Ok(msg) => {
                trace!("RelayMessage: {:#?}", msg);
                // get the inner msg from the option
                let inner_msg = match msg.opts().iter().find_map(|opt| match opt {
                    DhcpOption::RelayMsg(msg) => Some(msg),
                    _ => None,
                }) {
                    Some(v6::RelayMessageData::Message(m)) => m,
                    Some(v6::RelayMessageData::Relay(_rm)) => {
                        debug!("Ignoring nested relay message from {src}");
                        if let (Some(sinks), Some(relay_addr)) = (&event_channel, relay_addr) {
                            let event = DhcpEventV6::relay_failed(&msg, relay_addr, "NestedRelay");
                            sinks.send(DhcpEvent::V6(event));
                        }
                        continue;
                    }
                    None => {
                        debug!("Relay message from {src} carries no RelayMsg option");
                        if let (Some(sinks), Some(relay_addr)) = (&event_channel, relay_addr) {
                            let event = DhcpEventV6::relay_failed(&msg, relay_addr, "NoRelayMsg");
                            sinks.send(DhcpEvent::V6(event));
                        }
                        continue;
                    }
                };

                match crate::v6::handlers::handle_message(
                    &config.load(),
                    &reservations.load(),
                    &leases,
                    inner_msg,
                    &msg,
                ) {
                    DhcpV6Response::NoResponse(reason) => {
                        if !matches!(reason, NoResponse::NoReservation) {
                            debug!("Not responding {:?}", reason);
                        } else if tracing::enabled!(tracing::Level::INFO) {
                            let duid = inner_msg
                                .client_id()
                                .and_then(|b| Duid::new(b.to_vec()))
                                .map(|d| d.to_string());
                            let mac = msg.hw_addr().map(|m| m.to_string());
                            let option1837 = msg.option1837();
                            let interface_id =
                                option1837.as_ref().and_then(|o| o.interface.as_deref());
                            let remote_id = option1837.as_ref().and_then(|o| o.remote.as_deref());
                            info!(
                                duid = duid.as_deref(),
                                mac = mac.as_deref(),
                                interface_id,
                                remote_id,
                                relay = %src,
                                xid = ?inner_msg.xid(),
                                "DHCPv6: no reservation found — not responding"
                            );
                        }
                        if let (Some(sinks), Some(relay_addr)) = (&event_channel, relay_addr) {
                            let event =
                                DhcpEventV6::failed(inner_msg, &msg, relay_addr, reason.as_str());
                            sinks.send(DhcpEvent::V6(event));
                        }
                    }
                    DhcpV6Response::Message(resp) => {
                        // Capture before resp.message moves into the relay wrapper.
                        let reply_type = resp.message.msg_type();
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
                                if let (Some(sinks), Some(relay_addr)) =
                                    (&event_channel, relay_addr)
                                {
                                    let event = DhcpEventV6::send_failed(
                                        inner_msg,
                                        &msg,
                                        relay_addr,
                                        resp.reservation.as_deref(),
                                        resp.reservation_match,
                                        "EncodeFailed",
                                    );
                                    sinks.send(DhcpEvent::V6(event));
                                }
                                continue;
                            }
                        };
                        match socket.send_to(&write_buf, src) {
                            Ok(sent) => {
                                debug!("responded to {src} with {sent} bytes");
                                if tracing::enabled!(tracing::Level::INFO) {
                                    let duid = inner_msg
                                        .client_id()
                                        .and_then(|b| Duid::new(b.to_vec()))
                                        .map(|d| d.to_string());
                                    let mac = msg.hw_addr().map(|m| m.to_string());
                                    match resp.reservation.as_deref() {
                                        Some(reservation) => info!(
                                            message_type = ?reply_type,
                                            mac = mac.as_deref(),
                                            duid = duid.as_deref(),
                                            na = %reservation.ipv6_na,
                                            pd = %reservation.ipv6_pd,
                                            method = resp.reservation_match.map(|m| m.method),
                                            relay = %src,
                                            xid = ?inner_msg.xid(),
                                            "DHCPv6 lease granted"
                                        ),
                                        None => info!(
                                            mac = mac.as_deref(),
                                            duid = duid.as_deref(),
                                            relay = %src,
                                            xid = ?inner_msg.xid(),
                                            "DHCPv6 Reply sent with NoBinding — no reservation for renewing client"
                                        ),
                                    }
                                }
                                if let (Some(sinks), Some(relay_addr)) =
                                    (&event_channel, relay_addr)
                                {
                                    let event = DhcpEventV6::success(
                                        inner_msg,
                                        &msg,
                                        relay_addr,
                                        resp.reservation.as_deref(),
                                        resp.reservation_match,
                                    );
                                    sinks.send(DhcpEvent::V6(event));
                                }
                            }
                            Err(e) => {
                                error!("Problem sending response message: {e}");
                                if let (Some(sinks), Some(relay_addr)) =
                                    (&event_channel, relay_addr)
                                {
                                    let event = DhcpEventV6::send_failed(
                                        inner_msg,
                                        &msg,
                                        relay_addr,
                                        resp.reservation.as_deref(),
                                        resp.reservation_match,
                                        "SendFailed",
                                    );
                                    sinks.send(DhcpEvent::V6(event));
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Unable to parse dhcp message {}", e);
                if let (Some(sinks), Some(relay_addr)) = (&event_channel, relay_addr) {
                    sinks.send(DhcpEvent::V6(DhcpEventV6::parse_error(relay_addr)));
                }
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
