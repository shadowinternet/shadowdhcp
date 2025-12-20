use arc_swap::ArcSwapAny;
use dhcproto::{v4, Decodable, Encodable};
use std::{
    io,
    net::UdpSocket,
    sync::Arc,
};
use tracing::{debug, error, info, trace};

use shadow_dhcpv6::{config::Config, leasedb::LeaseDb, reservationdb::ReservationDb};

use crate::v4::handlers::handle_message;

pub fn v4_worker(
    reservations: Arc<ArcSwapAny<Arc<ReservationDb>>>,
    leases: Arc<LeaseDb>,
    config: Arc<ArcSwapAny<Arc<Config>>>,
) {
    let mut read_buf = [0u8; 2048];
    let bind_addr = std::env::var("SHADOW_DHCP4_BIND").unwrap_or("0.0.0.0:67".into());
    let socket = UdpSocket::bind(&bind_addr).expect("udp bind");
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
            Ok(msg) => {
                if let Some(response_msg) =
                    handle_message(&reservations.load(), &leases, &config.load(), msg)
                {
                    let write_buf = response_msg.to_vec().expect("encoding response message");
                    match socket.send_to(&write_buf, src) {
                        Ok(sent) => debug!("responded to {src} with {sent} bytes"),
                        Err(e) => error!("Problem sending response message: {e}"),
                    }
                }
            }
            Err(e) => {
                error!("Unable to parse dhcpv4 message {}", e);
            }
        }
    }
}
