use advmac::MacAddr6;
use dhcproto::v4::{self, DhcpOption, Flags};
use std::net::Ipv4Addr;
use tracing::{debug, error, field, info, instrument, warn, Span};

use shadow_dhcpv6::{config::Config, leasedb::LeaseDb, reservationdb::ReservationDb, V4Key};

use crate::v4::{
    extensions::ShadowMessageExtV4, reservation::find_reservation_by_relay_info,
    ADDRESS_LEASE_TIME, REBINDING_TIME, RENEWAL_TIME,
};

/// 4.3 A DHCP server can receive the following messages from a client:
/// * DHCPDISCOVER
/// * DHCPREQUEST
/// * DHCPDECLINE
/// * DHCPRELEASE
/// * DHCPINFORM
pub fn handle_message(
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
        v4::MessageType::Request => handle_request(reservations, leases, config, &msg),
        v4::MessageType::Decline => None,
        v4::MessageType::Release => None,
        // If a client has obtained a network address through some other means (e.g., manual configuration), it
        // may use a DHCPINFORM request message to obtain other local configuration parameters. Unicast reply sent
        // to the client.
        v4::MessageType::Inform => None,
        // Other messages are not valid for a server to receive
        _ => None,
    }
}

/// Client is discovering available DHCP servers, reply with DHCPOFFER message with
/// available parameters.
///
/// TODO: client renew
///
/// <https://datatracker.ietf.org/doc/html/rfc2131#section-4.3.1>
#[instrument(skip(reservations, config, msg),
fields(mac = field::Empty, xid = %msg.xid()))]
fn handle_discover(
    reservations: &ReservationDb,
    config: &Config,
    msg: &v4::Message,
) -> Option<v4::Message> {
    // get client hwaddr, or option82 key
    let mac_addr = MacAddr6::try_from(msg.chaddr()).ok()?;
    Span::current().record("mac", field::display(mac_addr));
    let relay = msg.relay_agent_information();
    info!("DHCPDiscover");

    // MAC reservations are higher priority than Option82:
    let reservation = match reservations
        .by_mac(mac_addr)
        .or(relay.and_then(|relay_info| {
            find_reservation_by_relay_info(reservations, &config.option82_extractors, relay_info)
        })) {
        Some(r) => {
            info!(ipv4 = %r.ipv4, "Found reservation for IP");
            r
        }
        None => {
            info!("No reservation found");
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
            error!("Couldn't find configured subnet for {}", &reservation.ipv4);
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
    opts.insert(DhcpOption::ServerIdentifier(config.v4_server_id));
    opts.insert(DhcpOption::SubnetMask(subnet_mask));
    opts.insert(DhcpOption::Router(vec![gateway]));
    opts.insert(DhcpOption::DomainNameServer(config.dns_v4.clone()));
    opts.insert(DhcpOption::AddressLeaseTime(ADDRESS_LEASE_TIME));
    opts.insert(DhcpOption::Renewal(RENEWAL_TIME));
    opts.insert(DhcpOption::Rebinding(REBINDING_TIME));
    opts.insert(DhcpOption::End);

    Some(reply)
}

/// DHCPREQUEST - Client message to servers either (a) requesting offered parameters from one server
/// and implicitly declining offers from all others, (b) confirming correctness of previously allocated
/// address after, e.g., system reboot, or (c) extending the lease on a particular network address
///
/// <https://datatracker.ietf.org/doc/html/rfc2131#section-4.3.2>
#[instrument(skip(reservations, config, msg, leases),
fields(mac = field::Empty, xid = %msg.xid()))]
fn handle_request(
    reservations: &ReservationDb,
    leases: &LeaseDb,
    config: &Config,
    msg: &v4::Message,
) -> Option<v4::Message> {
    // Four variants of DHCPREQUEST
    //  * SELECTING
    //    server id is set from the client and matches
    //    ciaddr must be zero
    //    requested ip address option must be filled with the value received previously in the DHCPOFFER from the server
    //    giaddr contains relay IP address
    //  * INIT/REBOOT
    //    no server id from client
    //    ciaddr must be zero
    //    requested ip address option must be filled
    //  * RENEW - client trying to extend its lease, sent unicast directly to server
    //    server id is not set
    //    ciaddr must be filled in
    //    requested ip address option is not filled in
    //  * REBINDING - when client can not reach server unicast, it broadcasts.
    //    same prereqs as RENEW, but sent via the relay

    let mac_addr = MacAddr6::try_from(msg.chaddr()).ok()?;
    let relay = msg.relay_agent_information();
    Span::current().record("mac", field::display(mac_addr));
    info!("DHCPRequest");

    // MAC reservations are higher priority than Option82:
    let reservation = match reservations
        .by_mac(mac_addr)
        .or(relay.and_then(|relay_info| {
            find_reservation_by_relay_info(reservations, &config.option82_extractors, relay_info)
        })) {
        Some(r) => {
            info!(ipv4 = %r.ipv4, "Found reservation for IP");
            r
        }
        None => {
            info!("No reservation found");
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
            warn!("Couldn't find configured subnet for {}", &reservation.ipv4);
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
    // TODO: check flags are correct
    reply.set_flags(msg.flags());
    reply.set_sname("dhcp.shadowinter.net".as_bytes());

    // select one of the four variants:
    let variant_tuple = (msg.server_id(), &msg.ciaddr(), msg.requested_ip_addr());
    let client_requested_ip = match variant_tuple {
        (Some(server_id), &Ipv4Addr::UNSPECIFIED, Some(requested_ip)) => {
            debug!("variant: selecting");
            if server_id != &config.v4_server_id {
                info!(%server_id, "SELECTING server id did not match");
                return None;
            }
            requested_ip
        }
        (None, &Ipv4Addr::UNSPECIFIED, Some(requested_ip)) => {
            debug!("variant: init-reboot");
            requested_ip
        }
        (None, ciaddr, None) if ciaddr != &Ipv4Addr::UNSPECIFIED => {
            if msg.giaddr() == Ipv4Addr::UNSPECIFIED {
                debug!("variant: renew")
            } else {
                debug!("variant: rebinding")
            }
            ciaddr
        }
        _ => {
            info!("Unrecognized DHCPREQUEST variant");
            return None;
        }
    };

    if client_requested_ip == &reservation.ipv4 {
        // the server selected in the DHCPREQUEST message commits the binding, and responds with a DHCPACK message
        // containing the configuration parameters for the requesting client. The combination of 'client identifier'
        // or 'chaddr' and assigned network address constitute a unique identifier for the client's lease.
        // If the server is unable to satisfy the DHCPREQUEST message (e.g., the address is already allocated) the
        // server should respond with a DHCPNAK message.
        let opts = reply.opts_mut();
        opts.insert(DhcpOption::MessageType(v4::MessageType::Ack));
        opts.insert(DhcpOption::ServerIdentifier(config.v4_server_id));
        opts.insert(DhcpOption::SubnetMask(subnet_mask));
        opts.insert(DhcpOption::Router(vec![gateway]));
        opts.insert(DhcpOption::DomainNameServer(config.dns_v4.clone()));
        opts.insert(DhcpOption::AddressLeaseTime(ADDRESS_LEASE_TIME));
        opts.insert(DhcpOption::Renewal(RENEWAL_TIME));
        opts.insert(DhcpOption::Rebinding(REBINDING_TIME));
        // TODO: add support for parameter request list option
        opts.insert(DhcpOption::End);

        // if option82, update the option82 to MAC address mapping:
        if let Some(V4Key::Option82(opt)) = reservation.v4_key() {
            leases.insert_mac_option82_binding(&mac_addr, &opt);
        }
    } else {
        warn!(reservation_ipv4 = %reservation.ipv4, %client_requested_ip,
            "client requested ip doesn't match reserved address, sending DHCPNAK",
        );
        // RFC 2131 Table 3: yiaddr in DHCPNAK MUST be 0
        reply.set_yiaddr(Ipv4Addr::UNSPECIFIED);
        if msg.giaddr() != Ipv4Addr::UNSPECIFIED {
            // init-reboot NAK should set broadcast bit when relayed
            let flags = reply.flags();
            reply.set_flags(Flags::set_broadcast(flags));
        }
        let opts = reply.opts_mut();
        opts.insert(DhcpOption::MessageType(v4::MessageType::Nak));
        opts.insert(DhcpOption::ServerIdentifier(config.v4_server_id));
        opts.insert(DhcpOption::End);
    }

    Some(reply)
}
