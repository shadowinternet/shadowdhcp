#![allow(unused)]
use advmac::MacAddr6;
use dhcproto::{
    v4::{self, relay, DhcpOption},
    Decodable, Encodable,
};
use std::{
    io,
    net::{Ipv4Addr, UdpSocket},
};

use shadow_dhcpv6::{Storage, V4Key};

const ADDRESS_LEASE_TIME: u32 = 3600;

fn server_id() -> Ipv4Addr {
    Ipv4Addr::from([23, 159, 144, 10])
}

fn handle_message(storage: &mut Storage, msg: v4::Message) -> Option<v4::Message> {
    // servers should only respond to BootRequest messages
    let message_type = match msg.opcode() {
        v4::Opcode::BootRequest => match msg.message_type() {
            Some(dhcp) => dhcp,
            None => return None,
        },
        // Servers don't receive BootReply
        v4::Opcode::BootReply => return None,
        // Skip handling Unknown
        v4::Opcode::Unknown(_) => return None,
    };

    match message_type {
        v4::MessageType::Discover => handle_message_discover(storage, &msg),
        v4::MessageType::Offer => todo!(),
        v4::MessageType::Request => todo!(),
        v4::MessageType::Decline => todo!(),
        v4::MessageType::Ack => todo!(),
        v4::MessageType::Nak => todo!(),
        v4::MessageType::Release => todo!(),
        v4::MessageType::Inform => todo!(),
        v4::MessageType::ForceRenew => todo!(),
        v4::MessageType::LeaseQuery => todo!(),
        v4::MessageType::LeaseUnassigned => todo!(),
        v4::MessageType::LeaseUnknown => todo!(),
        v4::MessageType::LeaseActive => todo!(),
        v4::MessageType::BulkLeaseQuery => todo!(),
        v4::MessageType::LeaseQueryDone => todo!(),
        v4::MessageType::ActiveLeaseQuery => todo!(),
        v4::MessageType::LeaseQueryStatus => todo!(),
        v4::MessageType::Tls => todo!(),
        v4::MessageType::Unknown(_) => todo!(),
    }
}

/// Client is discovering available DHCP servers, reply with DHCPOFFER message with
/// available parameters. TODO: Section 4.1, 4.3.1
fn handle_message_discover(storage: &mut Storage, msg: &v4::Message) -> Option<v4::Message> {
    // get client hwaddr, or option82 key
    let mac_addr = MacAddr6::try_from(msg.chaddr()).ok()?;
    let relay = msg.relay_agent_information();

    // MAC reservations are higher priority than Option82:
    let reservation = match storage.v4_reservations.get(&V4Key::Mac(mac_addr)) {
        Some(r) => r,
        None => todo!("get info from relay fields and check for reservation"),
    };
    let unspecified = Ipv4Addr::UNSPECIFIED;
    let mut reply = v4::Message::new_with_id(
        msg.xid(),
        unspecified,
        reservation.to_owned(),
        unspecified,
        msg.giaddr(),
        msg.chaddr(),
    );
    reply.set_opcode(v4::Opcode::BootReply);
    reply.set_secs(0);
    reply.set_flags(msg.flags());
    reply.set_sname("dhcp.shadowinter.net".as_bytes());

    let mut opts = reply.opts_mut();

    opts.insert(DhcpOption::MessageType(v4::MessageType::Offer));
    opts.insert(DhcpOption::ServerIdentifier(server_id()));
    opts.insert(DhcpOption::SubnetMask(Ipv4Addr::from([255, 255, 255, 0])));
    opts.insert(DhcpOption::Router(vec![Ipv4Addr::from([192, 168, 1, 1])]));
    opts.insert(DhcpOption::DomainNameServer(vec![
        Ipv4Addr::from([8, 8, 8, 8]),
        Ipv4Addr::from([8, 8, 4, 4]),
    ]));
    opts.insert(DhcpOption::AddressLeaseTime(ADDRESS_LEASE_TIME));
    opts.insert(DhcpOption::End);

    Some(reply)
}

fn v4_worker(socket: UdpSocket, mut storage: Storage) {
    let mut read_buf = [0u8; 2048];

    loop {
        let (amount, src) = match socket.recv_from(&mut read_buf) {
            Ok((amount, src)) => {
                println!("Received {amount} bytes from {src:?}");
                println!("Data: {:x?}", &read_buf[..amount]);
                (amount, src)
            }
            Err(err) => {
                eprintln!("Error receiving: {err:?}");
                match err.kind() {
                    io::ErrorKind::ConnectionReset => {
                        eprintln!("Sent response to host that responded with ICMP unreachable");
                        continue;
                    }
                    _ => todo!(),
                }
            }
        };

        match v4::Message::from_bytes(&read_buf[..amount]) {
            Ok(msg) => {
                if let Some(response_msg) = handle_message(&mut storage, msg) {
                    let write_buf = response_msg.to_vec().expect("encoding response message");
                    match socket.send_to(&write_buf, src) {
                        Ok(sent) => println!("responded with {sent} bytes"),
                        Err(e) => eprintln!("Problem sending response message: {e}"),
                    }
                }
            }
            Err(e) => {
                eprintln!("Unable to parse dhcpv4 message {}", e);
            }
        }
    }
}

trait ShadowMessageExtV4 {
    fn message_type(&self) -> Option<&v4::MessageType>;
    fn relay_agent_information(&self) -> Option<&v4::relay::RelayAgentInformation>;
}

impl ShadowMessageExtV4 for v4::Message {
    fn message_type(&self) -> Option<&v4::MessageType> {
        self.opts().iter().map(|o| o.1).find_map(|opt| match opt {
            v4::DhcpOption::MessageType(mt) => Some(mt),
            _ => None,
        })
    }

    fn relay_agent_information(&self) -> Option<&v4::relay::RelayAgentInformation> {
        self.opts().iter().find_map(|o| match o.1 {
            v4::DhcpOption::RelayAgentInformation(relay) => Some(relay),
            _ => None,
        })
    }
}
