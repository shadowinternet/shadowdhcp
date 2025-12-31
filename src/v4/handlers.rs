use advmac::MacAddr6;
use dhcproto::v4::{self, DhcpOption, Flags};
use std::time::Duration;
use std::{net::Ipv4Addr, sync::Arc};
use tracing::{debug, error, field, info, instrument, warn, Span};

use shadow_dhcpv6::{Reservation, V4Key};

use crate::analytics::events::ReservationMatch;
use crate::config::Config;
use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;

use crate::v4::{
    extensions::ShadowMessageExtV4, reservation::find_reservation, ADDRESS_LEASE_TIME,
    REBINDING_TIME, RENEWAL_TIME,
};

/// A DHCPv4 response message produced by the server.
///
/// If a reservation was used to construct the message, it is included for logging
/// and observability
pub struct ResponseMessage {
    pub message: v4::Message,
    pub reservation: Option<Arc<Reservation>>,
    pub reservation_match: Option<ReservationMatch>,
}

#[derive(Debug, Copy, Clone)]
pub enum NoResponse {
    NoReservation,
    NoValidMac,
    NoServerSubnet,
    Discarded,
    WrongServerId,
    NoMessageType,
}

impl NoResponse {
    pub fn as_str(&self) -> &'static str {
        match self {
            NoResponse::NoReservation => "NoReservation",
            NoResponse::NoValidMac => "NoValidMac",
            NoResponse::NoServerSubnet => "NoServerSubnet",
            NoResponse::Discarded => "Discarded",
            NoResponse::WrongServerId => "WrongServerId",
            NoResponse::NoMessageType => "NoMessageType",
        }
    }
}

/// Result of processing an incoming DHCPv6 message.
///
/// `DhcpV4Response` indicates whether the server should send a DHCPv6
/// message back to the client or intentionally remain silent.
pub enum DhcpV4Response {
    Message(ResponseMessage),
    NoResponse(NoResponse),
}

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
    msg: &v4::Message,
) -> DhcpV4Response {
    // servers should only respond to BootRequest messages
    let message_type = match msg.opcode() {
        v4::Opcode::BootRequest => match msg.message_type() {
            Some(mt) => mt,
            None => return DhcpV4Response::NoResponse(NoResponse::NoMessageType),
        },
        // Servers don't receive BootReply
        v4::Opcode::BootReply => return DhcpV4Response::NoResponse(NoResponse::Discarded),
        // Skip handling Unknown
        v4::Opcode::Unknown(_) => return DhcpV4Response::NoResponse(NoResponse::Discarded),
    };

    match message_type {
        v4::MessageType::Discover => handle_discover(reservations, config, msg),
        v4::MessageType::Request => handle_request(reservations, leases, config, msg),
        v4::MessageType::Decline => DhcpV4Response::NoResponse(NoResponse::Discarded),
        v4::MessageType::Release => DhcpV4Response::NoResponse(NoResponse::Discarded),
        // If a client has obtained a network address through some other means (e.g., manual configuration), it
        // may use a DHCPINFORM request message to obtain other local configuration parameters. Unicast reply sent
        // to the client.
        v4::MessageType::Inform => DhcpV4Response::NoResponse(NoResponse::Discarded),
        // Other messages are not valid for a server to receive
        _ => DhcpV4Response::NoResponse(NoResponse::Discarded),
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
) -> DhcpV4Response {
    let mac_addr = match MacAddr6::try_from(msg.chaddr()).ok() {
        Some(ma) => ma,
        None => return DhcpV4Response::NoResponse(NoResponse::NoValidMac),
    };
    Span::current().record("mac", field::display(mac_addr));
    info!("DHCPDiscover");

    let (reservation, match_info) = match find_reservation(
        reservations,
        &config.option82_extractors,
        mac_addr,
        msg.relay_agent_information(),
    ) {
        Some((res, match_info)) => {
            info!(ipv4 = %res.ipv4, method = match_info.method, "Found reservation");
            (res, match_info)
        }
        None => {
            info!("No reservation found");
            return DhcpV4Response::NoResponse(NoResponse::NoReservation);
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
            return DhcpV4Response::NoResponse(NoResponse::NoServerSubnet);
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

    DhcpV4Response::Message(ResponseMessage {
        message: reply,
        reservation: Some(reservation),
        reservation_match: Some(match_info),
    })
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
) -> DhcpV4Response {
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

    let mac_addr = match MacAddr6::try_from(msg.chaddr()).ok() {
        Some(ma) => ma,
        None => return DhcpV4Response::NoResponse(NoResponse::NoValidMac),
    };
    Span::current().record("mac", field::display(mac_addr));
    info!("DHCPRequest");

    let (reservation, match_info) = match find_reservation(
        reservations,
        &config.option82_extractors,
        mac_addr,
        msg.relay_agent_information(),
    ) {
        Some((res, match_info)) => {
            info!(ipv4 = %res.ipv4, method = match_info.method, "Found reservation");
            (res, match_info)
        }
        None => {
            info!("No reservation found");
            return DhcpV4Response::NoResponse(NoResponse::NoReservation);
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
            return DhcpV4Response::NoResponse(NoResponse::NoServerSubnet);
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
                return DhcpV4Response::NoResponse(NoResponse::WrongServerId);
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
            return DhcpV4Response::NoResponse(NoResponse::Discarded);
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

        let opt82 = match reservation.v4_key() {
            Some(V4Key::Option82(opt)) => Some(opt),
            _ => None,
        };
        leases.lease_v4(
            &reservation,
            mac_addr,
            opt82,
            Duration::from_secs(u64::from(ADDRESS_LEASE_TIME)),
        );
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

    DhcpV4Response::Message(ResponseMessage {
        message: reply,
        reservation: Some(reservation),
        reservation_match: Some(match_info),
    })
}
