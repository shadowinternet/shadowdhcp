use arc_swap::ArcSwapAny;

use dhcproto::{
    v6::{self, DhcpOption, DhcpOptions, RelayMessage},
    Decodable, Encodable,
};

use shadow_dhcpv6::{config::Config, leasedb::LeaseDb, reservationdb::ReservationDb};
use std::{fmt::Write, io, net::UdpSocket, sync::Arc};
use tracing::{debug, error, info, trace};

pub fn v6_worker(
    reservations: Arc<ArcSwapAny<Arc<ReservationDb>>>,
    leases: Arc<LeaseDb>,
    config: Arc<ArcSwapAny<Arc<Config>>>,
) {
    // only work with relayed messages
    let bind_addr = std::env::var("SHADOW_DHCP6_BIND").unwrap_or("[::]:547".into());
    let socket = UdpSocket::bind(&bind_addr).expect("udp bind");
    info!("Successfully bound to: {bind_addr}");
    let mut read_buf = [0u8; 2048];

    // listen for messages
    loop {
        // if the src is not listening on response, it may send a ICMP host unreachable
        let (amount, src) = match socket.recv_from(&mut read_buf) {
            Ok((amount, src)) => {
                debug!("Received {amount} bytes from {src:?}");
                trace!("Data: {}", hex_for_text2pcap(&read_buf[..amount]));
                (amount, src)
            }
            Err(err) => {
                error!("Error receiving: {err:?}");
                match err.kind() {
                    io::ErrorKind::NotFound => todo!(),
                    io::ErrorKind::PermissionDenied => todo!(),
                    io::ErrorKind::ConnectionRefused => todo!(),
                    io::ErrorKind::ConnectionReset => {
                        error!("Sent response to host that responded with ICMP unreachable");
                        continue;
                    }
                    io::ErrorKind::ConnectionAborted => todo!(),
                    io::ErrorKind::NotConnected => todo!(),
                    io::ErrorKind::AddrInUse => todo!(),
                    io::ErrorKind::AddrNotAvailable => todo!(),
                    io::ErrorKind::BrokenPipe => todo!(),
                    io::ErrorKind::AlreadyExists => todo!(),
                    io::ErrorKind::WouldBlock => todo!(),
                    io::ErrorKind::InvalidInput => todo!(),
                    io::ErrorKind::InvalidData => todo!(),
                    io::ErrorKind::TimedOut => todo!(),
                    io::ErrorKind::WriteZero => todo!(),
                    io::ErrorKind::Interrupted => todo!(),
                    io::ErrorKind::Unsupported => todo!(),
                    io::ErrorKind::UnexpectedEof => todo!(),
                    io::ErrorKind::OutOfMemory => todo!(),
                    io::ErrorKind::Other => todo!(),
                    _ => todo!(),
                }
            }
        };
        match v6::RelayMessage::from_bytes(&read_buf[..amount]) {
            Ok(msg) => {
                trace!("RelayMessage: {:#?}", msg);
                // get the inner msg from the option
                let inner_msg = match msg.opts().iter().find_map(|opt| match opt {
                    DhcpOption::RelayMsg(msg) => Some(msg.clone()),
                    _ => None,
                }) {
                    Some(msg) => match msg {
                        v6::RelayMessageData::Message(m) => m,
                        v6::RelayMessageData::Relay(_rm) => continue,
                    },
                    None => continue,
                };

                if let Some(response_msg) = crate::v6::handlers::handle_message(
                    &config.load(),
                    &reservations.load(),
                    &leases,
                    inner_msg,
                    &msg,
                ) {
                    // wrap the message in a RelayRepl
                    let mut relay_reply_opts = DhcpOptions::new();
                    relay_reply_opts.insert(DhcpOption::RelayMsg(v6::RelayMessageData::Message(
                        response_msg,
                    )));

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

                    let write_buf = relay_msg.to_vec().expect("encoding response msg");
                    match socket.send_to(&write_buf, src) {
                        Ok(sent) => debug!("responded with {sent} bytes"),
                        Err(e) => error!("Problem sending respones message: {e}"),
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
