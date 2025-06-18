use advmac::MacAddr6;
use arc_swap::ArcSwapAny;
use compact_str::CompactString;
use dhcproto::{
    v4::{self, relay::RelayAgentInformation, DhcpOption},
    Decodable, Encodable,
};
use std::{
    io,
    net::{Ipv4Addr, UdpSocket},
    sync::Arc,
};

use shadow_dhcpv6::{
    leasedb::LeaseDb, reservationdb::ReservationDb, Config, Option82, RelayAgentInformationExt,
    Reservation, V4Key,
};

const ADDRESS_LEASE_TIME: u32 = 3600;

fn server_id() -> Ipv4Addr {
    Ipv4Addr::from([23, 159, 144, 10])
}

/// 4.3 A DHCP server can receive the following messages from a client:
/// * DHCPDISCOVER
/// * DHCPREQUEST
/// * DHCPDECLINE
/// * DHCPRELEASE
/// * DHCPINFORM
fn handle_message(
    reservations: &ReservationDb,
    leases: &LeaseDb,
    config: &Config,
    msg: v4::Message,
) -> Option<v4::Message> {
    // servers should only respond to BootRequest messages
    let message_type = match msg.opcode() {
        v4::Opcode::BootRequest => msg.message_type()?,
        // Servers don't receive BootReply
        v4::Opcode::BootReply => return None,
        // Skip handling Unknown
        v4::Opcode::Unknown(_) => return None,
    };

    match message_type {
        v4::MessageType::Discover => handle_discover(reservations, config, &msg),
        v4::MessageType::Offer => None,
        v4::MessageType::Request => handle_request(reservations, leases, config, &msg),
        v4::MessageType::Decline => todo!(),
        v4::MessageType::Ack => None,
        v4::MessageType::Nak => None,
        v4::MessageType::Release => todo!(),
        v4::MessageType::Inform => todo!(),
        v4::MessageType::ForceRenew => None,
        v4::MessageType::LeaseQuery => None,
        v4::MessageType::LeaseUnassigned => None,
        v4::MessageType::LeaseUnknown => None,
        v4::MessageType::LeaseActive => None,
        v4::MessageType::BulkLeaseQuery => None,
        v4::MessageType::LeaseQueryDone => None,
        v4::MessageType::ActiveLeaseQuery => None,
        v4::MessageType::LeaseQueryStatus => None,
        v4::MessageType::Tls => None,
        v4::MessageType::Unknown(_) => None,
    }
}

/// Client is discovering available DHCP servers, reply with DHCPOFFER message with
/// available parameters.
///
/// TODO: client renew
///
/// <https://datatracker.ietf.org/doc/html/rfc2131#section-4.3.1>
fn handle_discover(
    reservations: &ReservationDb,
    config: &Config,
    msg: &v4::Message,
) -> Option<v4::Message> {
    println!("DHCPDiscover");
    // get client hwaddr, or option82 key
    let mac_addr = MacAddr6::try_from(msg.chaddr()).ok()?;
    let relay = msg.relay_agent_information();

    // MAC reservations are higher priority than Option82:
    let reservation = match reservations
        .by_mac(&mac_addr)
        .or(relay.and_then(|relay_info| {
            get_reservation_by_relay_information(reservations, config, relay_info)
        })) {
        Some(r) => {
            println!("Found reservation for IP: {}", r.ipv4);
            r
        }
        None => {
            println!("No reservation for ___ ");
            // Ignore messages that don't have a reservation
            return None;
        }
    };

    let (gateway, subnet_mask) = match config
        .subnets_v4
        .iter()
        .find(|subnet| subnet.net.contains(&reservation.ipv4))
        .map(|subnet| (subnet.gateway, subnet.net.netmask()))
    {
        Some((gw, subnet)) => (gw, subnet),
        None => {
            eprintln!("Couldn't find configured subnet for {}", &reservation.ipv4);
            return None;
        }
    };

    let unspecified = Ipv4Addr::UNSPECIFIED;
    let mut reply = v4::Message::new_with_id(
        msg.xid(),
        unspecified,
        reservation.ipv4,
        unspecified,
        msg.giaddr(),
        msg.chaddr(),
    );
    reply.set_opcode(v4::Opcode::BootReply);
    reply.set_secs(0);
    reply.set_flags(msg.flags());
    reply.set_sname("dhcp.shadowinter.net".as_bytes());

    let opts = reply.opts_mut();

    opts.insert(DhcpOption::MessageType(v4::MessageType::Offer));
    opts.insert(DhcpOption::ServerIdentifier(server_id()));
    opts.insert(DhcpOption::SubnetMask(subnet_mask));
    opts.insert(DhcpOption::Router(vec![gateway]));
    opts.insert(DhcpOption::DomainNameServer(config.dns_v4.clone()));
    opts.insert(DhcpOption::AddressLeaseTime(ADDRESS_LEASE_TIME));
    opts.insert(DhcpOption::End);

    Some(reply)
}

/// DHCPREQUEST - Client message to servers either (a) requesting offered parameters from one server
/// and implicitly declining offers from all others, (b) confirming correctness of previously allocated
/// address after, e.g., system reboot, or (c) extending the lease on a particular network address
fn handle_request(
    reservations: &ReservationDb,
    leases: &LeaseDb,
    config: &Config,
    msg: &v4::Message,
) -> Option<v4::Message> {
    println!("DHCPRequest");
    // client MUST include the 'server identifier' for this server
    if msg.server_id()? != &server_id() {
        println!(
            "DHCPREQUEST message includes Server ID that doesn't match this server: {:?}",
            msg.server_id()
        );
        return None;
    }

    // get client hwaddr, or option82 key
    let mac_addr = MacAddr6::try_from(msg.chaddr()).ok()?;
    let relay = msg.relay_agent_information();

    // MAC reservations are higher priority than Option82:
    let reservation = match reservations
        .by_mac(&mac_addr)
        .or(relay.and_then(|relay_info| {
            get_reservation_by_relay_information(reservations, config, relay_info)
        })) {
        Some(r) => r,
        None => {
            println!("No reservation for ___ ");
            return None;
        }
    };

    let (gateway, subnet_mask) = match config
        .subnets_v4
        .iter()
        .find(|subnet| subnet.net.contains(&reservation.ipv4))
        .map(|subnet| (subnet.gateway, subnet.net.netmask()))
    {
        Some((gw, subnet)) => (gw, subnet),
        None => {
            eprintln!("Couldn't find configured subnet for {}", &reservation.ipv4);
            return None;
        }
    };

    let unspecified = Ipv4Addr::UNSPECIFIED;
    let mut reply = v4::Message::new_with_id(
        msg.xid(),
        unspecified,
        reservation.ipv4,
        unspecified,
        msg.giaddr(),
        msg.chaddr(),
    );
    reply.set_opcode(v4::Opcode::BootReply);
    reply.set_secs(0);
    reply.set_flags(msg.flags());
    reply.set_sname("dhcp.shadowinter.net".as_bytes());

    let opts = reply.opts_mut();

    // the 'requested IP address' option MUST be set to the value of 'yiaddr' in the DHCPOFFER message
    // from the server
    if msg.requested_ip_addr() == Some(&reservation.ipv4) {
        // the server selected in the DHCPREQUEST message commits the binding, and responds with a DHCPACK message
        // containing the configuration parameters for the requesting client. The combination of 'client identifier'
        // or 'chaddr' and assigned network address constitute a unique identifier for the client's lease.
        // If the server is unable to satisfy the DHCPREQUEST message (e.g., the address is already allocated) the
        // server should respond with a DHCPNAK message.
        opts.insert(DhcpOption::MessageType(v4::MessageType::Ack));
        opts.insert(DhcpOption::ServerIdentifier(server_id()));
        opts.insert(DhcpOption::SubnetMask(subnet_mask));
        opts.insert(DhcpOption::Router(vec![gateway]));
        opts.insert(DhcpOption::DomainNameServer(config.dns_v4.clone()));
        opts.insert(DhcpOption::AddressLeaseTime(ADDRESS_LEASE_TIME));
        opts.insert(DhcpOption::End);

        // if option82, update the option82 to MAC address mapping:
        if let Some(V4Key::Option82(opt)) = reservation.v4_key() {
            leases.insert_mac_option82_binding(&mac_addr, &opt);
        }
    } else {
        println!(
            "DHCPREQUEST message requested ip {:?} doesn't match reserved address: {:?}, sending DHCPNAK",
            msg.requested_ip_addr(),
            reservation
        );
        opts.insert(DhcpOption::MessageType(v4::MessageType::Nak));
        opts.insert(DhcpOption::ServerIdentifier(server_id()));
        opts.insert(DhcpOption::End);
    }

    Some(reply)
}

fn get_reservation_by_relay_information(
    reservations: &ReservationDb,
    config: &Config,
    relay: &RelayAgentInformation,
) -> Option<Arc<Reservation>> {
    let circuit = relay
        .circuit_id()
        .and_then(|v| CompactString::from_utf8(v).ok());
    let remote = relay
        .remote_id()
        .and_then(|v| CompactString::from_utf8(v).ok());
    let subscriber = relay
        .subscriber_id()
        .and_then(|v| CompactString::from_utf8(v).ok());

    let option = Option82 {
        circuit,
        remote,
        subscriber,
    };

    println!("{option:?}");

    config.option82_extractors.iter().find_map(|extractor| {
        extractor(&option).and_then(|extracted_opt| reservations.by_opt82(&extracted_opt))
    })
}

pub fn v4_worker(
    reservations: Arc<ArcSwapAny<Arc<ReservationDb>>>,
    leases: Arc<LeaseDb>,
    config: Arc<ArcSwapAny<Arc<Config>>>,
) {
    let mut read_buf = [0u8; 2048];
    let bind_addr = std::env::var("SHADOW_DHCP4_BIND").unwrap_or("0.0.0.0:67".into());
    let socket = UdpSocket::bind(&bind_addr).expect("udp bind");
    println!("Successfully bound to: {bind_addr}");

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
                if let Some(response_msg) =
                    handle_message(&reservations.load(), &leases, &config.load(), msg)
                {
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
    fn server_id(&self) -> Option<&Ipv4Addr>;
    fn requested_ip_addr(&self) -> Option<&Ipv4Addr>;
    fn relay_agent_information(&self) -> Option<&v4::relay::RelayAgentInformation>;
}

impl ShadowMessageExtV4 for v4::Message {
    fn message_type(&self) -> Option<&v4::MessageType> {
        self.opts().iter().find_map(|o| match o.1 {
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

    fn server_id(&self) -> Option<&Ipv4Addr> {
        self.opts().iter().find_map(|o| match o.1 {
            v4::DhcpOption::ServerIdentifier(addr) => Some(addr),
            _ => None,
        })
    }

    fn requested_ip_addr(&self) -> Option<&Ipv4Addr> {
        self.opts().iter().find_map(|o| match o.1 {
            v4::DhcpOption::RequestedIpAddress(addr) => Some(addr),
            _ => None,
        })
    }
}
