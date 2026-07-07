use arc_swap::ArcSwap;
use dhcproto::{v4, Decodable, Encodable};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, error, info, trace};

use crate::config::Config;
use crate::opt82_cache::Opt82Cache;
use crate::reservationdb::ReservationDb;
use crate::shutdown::Shutdown;

use advmac::MacAddr6;

use crate::{
    analytics::{
        events::{DhcpEvent, DhcpEventV4},
        EventSenders,
    },
    v4::extensions::{RelayAgentInformationExt, ShadowMessageExtV4},
    v4::handlers::{handle_message, DhcpV4Response, NoResponse, ResponseMessage},
};

pub fn v4_worker(
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
        .expect("set v4 socket read timeout");

    loop {
        if shutdown.is_signalled() {
            info!("v4 worker shutting down");
            return;
        }
        let (amount, src) = match socket.recv_from(&mut read_buf) {
            Ok((amount, src)) => {
                error_count = 0;
                debug!("Received {amount} bytes from {src:?}");
                trace!("Data: {:x?}", &read_buf[..amount]);
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
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        };

        match v4::Message::from_bytes(&read_buf[..amount]) {
            Ok(msg) => match handle_message(&reservations.load(), &leases, &config.load(), &msg) {
                DhcpV4Response::NoResponse(reason) => {
                    if !matches!(reason, NoResponse::NoReservation) {
                        debug!("Not responding {:?}", reason);
                    } else if tracing::enabled!(tracing::Level::INFO) {
                        let relay_info = msg.relay_agent_information();
                        let circuit = relay_info
                            .and_then(|r| r.circuit_id())
                            .map(|b| String::from_utf8_lossy(&b).into_owned());
                        let remote = relay_info
                            .and_then(|r| r.remote_id())
                            .map(|b| String::from_utf8_lossy(&b).into_owned());
                        let subscriber = relay_info
                            .and_then(|r| r.subscriber_id())
                            .map(|b| String::from_utf8_lossy(&b).into_owned());
                        let mac = MacAddr6::try_from(msg.chaddr()).ok().map(|m| m.to_string());
                        info!(
                            mac = mac.as_deref(),
                            circuit = circuit.as_deref(),
                            remote = remote.as_deref(),
                            subscriber = subscriber.as_deref(),
                            relay = %msg.giaddr(),
                            xid = msg.xid(),
                            "DHCPv4: no reservation found — not responding"
                        );
                    }
                    if let (Some(sinks), Some(relay_addr)) = (&event_channel, relay_addr) {
                        let event = DhcpEventV4::failed(&msg, relay_addr, reason.as_str());
                        sinks.send(DhcpEvent::V4(event));
                    }
                }
                DhcpV4Response::Message(resp) => {
                    let write_buf = match resp.message.to_vec() {
                        Ok(buf) => buf,
                        Err(e) => {
                            error!("Failed to encode DHCPv4 response: {e}");
                            if let (Some(sinks), Some(relay_addr)) = (&event_channel, relay_addr) {
                                let event = DhcpEventV4::send_failed(
                                    &msg,
                                    relay_addr,
                                    resp.reservation.as_deref(),
                                    resp.reservation_match,
                                    "EncodeFailed",
                                );
                                sinks.send(DhcpEvent::V4(event));
                            }
                            continue;
                        }
                    };
                    match socket.send_to(&write_buf, src) {
                        Ok(sent) => {
                            debug!("responded to {src} with {sent} bytes");
                            log_send_outcome(&msg, &resp);
                            if let (Some(sinks), Some(relay_addr)) = (&event_channel, relay_addr) {
                                let event = DhcpEventV4::success(
                                    &msg,
                                    relay_addr,
                                    resp.reservation.as_deref(),
                                    resp.reservation_match,
                                );
                                sinks.send(DhcpEvent::V4(event));
                            }
                        }
                        Err(e) => {
                            error!("Problem sending response message: {e}");
                            if let (Some(sinks), Some(relay_addr)) = (&event_channel, relay_addr) {
                                let event = DhcpEventV4::send_failed(
                                    &msg,
                                    relay_addr,
                                    resp.reservation.as_deref(),
                                    resp.reservation_match,
                                    "SendFailed",
                                );
                                sinks.send(DhcpEvent::V4(event));
                            }
                        }
                    }
                }
            },
            Err(e) => {
                error!("Unable to parse dhcpv4 message {}", e);
                if let (Some(sinks), Some(relay_addr)) = (&event_channel, relay_addr) {
                    sinks.send(DhcpEvent::V4(DhcpEventV4::parse_error(relay_addr)));
                }
            }
        }
    }
}

/// One human-readable line per sent transaction, logged at the send path so
/// it reflects what actually went out on the wire.
fn log_send_outcome(msg: &v4::Message, resp: &ResponseMessage) {
    if !tracing::enabled!(tracing::Level::INFO) {
        return;
    }
    let mac = MacAddr6::try_from(msg.chaddr()).ok().map(|m| m.to_string());
    match resp.message.message_type() {
        Some(v4::MessageType::Offer) => info!(
            mac = mac.as_deref(),
            ip = %resp.message.yiaddr(),
            method = resp.reservation_match.map(|m| m.method),
            relay = %msg.giaddr(),
            xid = msg.xid(),
            "DHCPv4 lease offered"
        ),
        Some(v4::MessageType::Ack) => info!(
            mac = mac.as_deref(),
            ip = %resp.message.yiaddr(),
            method = resp.reservation_match.map(|m| m.method),
            relay = %msg.giaddr(),
            xid = msg.xid(),
            "DHCPv4 lease acknowledged"
        ),
        Some(v4::MessageType::Nak) => info!(
            mac = mac.as_deref(),
            relay = %msg.giaddr(),
            xid = msg.xid(),
            "DHCPv4 NAK sent — requested address does not match reservation"
        ),
        _ => {}
    }
}
