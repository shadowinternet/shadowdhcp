#![cfg(test)]

use advmac::MacAddr6;
use dhcproto::v4::{self, DhcpOption, Flags, Opcode};
use ipnet::Ipv6Net;
use shadow_dhcpv6::{Duid, Option82, Reservation, V4Subnet};

use crate::config::Config;
use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;
use crate::v4::extractors;
use std::net::Ipv4Addr;

use crate::v4::{
    extensions::ShadowMessageExtV4,
    handlers::{handle_message, DhcpV4Response},
    ADDRESS_LEASE_TIME, REBINDING_TIME, RENEWAL_TIME,
};

const TEST_MAC: MacAddr6 = MacAddr6::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
const TEST_MAC_2: MacAddr6 = MacAddr6::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

fn create_test_env() -> (Config, ReservationDb, LeaseDb) {
    let config = Config {
        v4_server_id: Ipv4Addr::new(10, 0, 0, 1),
        dns_v4: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
        subnets_v4: vec![
            V4Subnet {
                net: "192.168.1.0/24".parse().unwrap(),
                gateway: Ipv4Addr::new(192, 168, 1, 1),
            },
            V4Subnet {
                net: "10.10.0.0/16".parse().unwrap(),
                gateway: Ipv4Addr::new(10, 10, 0, 1),
            },
        ],
        v6_server_id: Duid::from(vec![0, 1, 2, 3]),
        option82_extractors: extractors::get_all_extractors().into_values().collect(),
        option1837_extractors: vec![],
        log_level: tracing::Level::INFO,
        events_address: None,
    };

    let reservations = ReservationDb::new();

    // MAC-based reservation
    let reservation_mac = Reservation {
        ipv4: Ipv4Addr::new(192, 168, 1, 100),
        ipv6_na: "2001:db8::100".parse().unwrap(),
        ipv6_pd: "2001:db8:100::/56".parse::<Ipv6Net>().unwrap(),
        mac: Some(TEST_MAC),
        duid: None,
        option82: None,
        option1837: None,
    };
    reservations.insert(reservation_mac);

    // Option82-based reservation (remote_id only)
    let reservation_opt82 = Reservation {
        ipv4: Ipv4Addr::new(192, 168, 1, 200),
        ipv6_na: "2001:db8::200".parse().unwrap(),
        ipv6_pd: "2001:db8:200::/56".parse::<Ipv6Net>().unwrap(),
        mac: None,
        duid: None,
        option82: Some(Option82 {
            circuit: None,
            remote: Some("switch1:port1".into()),
            subscriber: None,
        }),
        option1837: None,
    };
    reservations.insert(reservation_opt82);

    // Reservation with both MAC and Option82 (MAC should take priority)
    let reservation_both = Reservation {
        ipv4: Ipv4Addr::new(10, 10, 1, 50),
        ipv6_na: "2001:db8::50".parse().unwrap(),
        ipv6_pd: "2001:db8:50::/56".parse::<Ipv6Net>().unwrap(),
        mac: Some(TEST_MAC_2),
        duid: None,
        option82: Some(Option82 {
            circuit: None,
            remote: Some("fallback-remote".into()),
            subscriber: None,
        }),
        option1837: None,
    };
    reservations.insert(reservation_both);

    let leases = LeaseDb::new();

    (config, reservations, leases)
}

fn create_discover(mac: MacAddr6, xid: u32) -> v4::Message {
    let mut msg = v4::Message::new_with_id(
        xid,
        Ipv4Addr::UNSPECIFIED, // ciaddr
        Ipv4Addr::UNSPECIFIED, // yiaddr
        Ipv4Addr::UNSPECIFIED, // siaddr
        Ipv4Addr::UNSPECIFIED, // giaddr
        &mac.to_array(),
    );
    msg.set_opcode(Opcode::BootRequest);
    msg.opts_mut()
        .insert(DhcpOption::MessageType(v4::MessageType::Discover));
    msg
}

fn create_request_selecting(
    mac: MacAddr6,
    xid: u32,
    server_id: Ipv4Addr,
    requested_ip: Ipv4Addr,
) -> v4::Message {
    let mut msg = v4::Message::new_with_id(
        xid,
        Ipv4Addr::UNSPECIFIED, // ciaddr must be zero
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        &mac.to_array(),
    );
    msg.set_opcode(Opcode::BootRequest);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::MessageType(v4::MessageType::Request));
    opts.insert(DhcpOption::ServerIdentifier(server_id));
    opts.insert(DhcpOption::RequestedIpAddress(requested_ip));
    msg
}

fn create_request_init_reboot(mac: MacAddr6, xid: u32, requested_ip: Ipv4Addr) -> v4::Message {
    let mut msg = v4::Message::new_with_id(
        xid,
        Ipv4Addr::UNSPECIFIED, // ciaddr must be zero
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        &mac.to_array(),
    );
    msg.set_opcode(Opcode::BootRequest);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::MessageType(v4::MessageType::Request));
    // No server_id for INIT-REBOOT
    opts.insert(DhcpOption::RequestedIpAddress(requested_ip));
    msg
}

fn create_request_renew(mac: MacAddr6, xid: u32, ciaddr: Ipv4Addr) -> v4::Message {
    let mut msg = v4::Message::new_with_id(
        xid,
        ciaddr, // ciaddr must be filled
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED, // giaddr is zero for RENEW (unicast)
        &mac.to_array(),
    );
    msg.set_opcode(Opcode::BootRequest);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::MessageType(v4::MessageType::Request));
    // No server_id, no requested_ip for RENEW
    msg
}

fn create_request_rebinding(
    mac: MacAddr6,
    xid: u32,
    ciaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
) -> v4::Message {
    let mut msg = v4::Message::new_with_id(
        xid,
        ciaddr, // ciaddr must be filled
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        giaddr, // giaddr is set for REBINDING (broadcast via relay)
        &mac.to_array(),
    );
    msg.set_opcode(Opcode::BootRequest);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::MessageType(v4::MessageType::Request));
    // No server_id, no requested_ip for REBINDING
    msg
}

// ============================================================================
// DISCOVER Tests
// ============================================================================

#[test]
fn discover_with_mac_reservation_returns_offer() {
    let (config, reservations, leases) = create_test_env();
    let msg = create_discover(TEST_MAC, 0x12345678);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Offer));
    assert_eq!(reply.yiaddr(), Ipv4Addr::new(192, 168, 1, 100));
}

#[test]
fn discover_with_option82_reservation_returns_offer() {
    let (config, reservations, leases) = create_test_env();
    let unknown_mac = MacAddr6::new([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]);
    let mut msg = create_discover(unknown_mac, 0xABCDEF00);

    // Add Option82 relay agent information
    let mut relay_info = dhcproto::v4::relay::RelayAgentInformation::default();
    relay_info.insert(dhcproto::v4::relay::RelayInfo::AgentRemoteId(
        b"switch1:port1".to_vec(),
    ));
    msg.opts_mut()
        .insert(DhcpOption::RelayAgentInformation(relay_info));

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Offer));
    assert_eq!(reply.yiaddr(), Ipv4Addr::new(192, 168, 1, 200));
}

#[test]
fn discover_echoes_xid() {
    let (config, reservations, leases) = create_test_env();
    let xid = 0xDEADBEEF;
    let msg = create_discover(TEST_MAC, xid);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    assert_eq!(reply.xid(), xid);
}

#[test]
fn discover_echoes_chaddr() {
    let (config, reservations, leases) = create_test_env();
    let msg = create_discover(TEST_MAC, 0x11111111);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    assert_eq!(&reply.chaddr()[0..6], &TEST_MAC.to_array());
}

#[test]
fn discover_preserves_giaddr() {
    let (config, reservations, leases) = create_test_env();
    let mut msg = create_discover(TEST_MAC, 0x22222222);
    let relay_ip = Ipv4Addr::new(192, 168, 1, 254);
    msg.set_giaddr(relay_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    assert_eq!(reply.giaddr(), relay_ip);
}

#[test]
fn discover_sets_correct_yiaddr() {
    let (config, reservations, leases) = create_test_env();
    let msg = create_discover(TEST_MAC, 0x33333333);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    // Should be the reserved IP for TEST_MAC
    assert_eq!(reply.yiaddr(), Ipv4Addr::new(192, 168, 1, 100));
}

#[test]
fn discover_includes_required_options() {
    let (config, reservations, leases) = create_test_env();
    let msg = create_discover(TEST_MAC, 0x44444444);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    // Check MessageType
    assert_eq!(reply.message_type(), Some(&v4::MessageType::Offer));

    // Check ServerIdentifier
    assert_eq!(reply.server_id(), Some(&config.v4_server_id));

    // Check SubnetMask is present
    let has_subnet_mask = reply.opts().iter().any(|(_, opt)| {
        matches!(opt, DhcpOption::SubnetMask(mask) if *mask == Ipv4Addr::new(255, 255, 255, 0))
    });
    assert!(has_subnet_mask, "SubnetMask option missing");

    // Check Router is present
    let has_router = reply.opts().iter().any(|(_, opt)| {
        matches!(opt, DhcpOption::Router(routers) if routers.contains(&Ipv4Addr::new(192, 168, 1, 1)))
    });
    assert!(has_router, "Router option missing");

    // Check DNS servers are present
    let has_dns = reply
        .opts()
        .iter()
        .any(|(_, opt)| matches!(opt, DhcpOption::DomainNameServer(servers) if servers.len() == 2));
    assert!(has_dns, "DomainNameServer option missing");

    // Check AddressLeaseTime
    let has_lease_time = reply.opts().iter().any(
        |(_, opt)| matches!(opt, DhcpOption::AddressLeaseTime(time) if *time == ADDRESS_LEASE_TIME),
    );
    assert!(has_lease_time, "AddressLeaseTime option missing");
}

#[test]
fn discover_no_reservation_returns_none() {
    let (config, reservations, leases) = create_test_env();
    let unknown_mac = MacAddr6::new([0x99, 0x99, 0x99, 0x99, 0x99, 0x99]);
    let msg = create_discover(unknown_mac, 0x55555555);

    let reply = handle_message(&reservations, &leases, &config, &msg);

    assert!(
        matches!(reply, DhcpV4Response::NoResponse(_)),
        "Should not respond when no reservation exists"
    );
}

#[test]
fn discover_reservation_not_in_subnet_returns_none() {
    let (config, reservations, leases) = create_test_env();

    // Add a reservation with an IP not in any configured subnet
    let bad_reservation = Reservation {
        ipv4: Ipv4Addr::new(172, 16, 0, 1), // Not in 192.168.1.0/24 or 10.10.0.0/16
        ipv6_na: "2001:db8::bad".parse().unwrap(),
        ipv6_pd: "2001:db8:bad::/56".parse::<Ipv6Net>().unwrap(),
        mac: Some(MacAddr6::new([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])),
        duid: None,
        option82: None,
        option1837: None,
    };
    reservations.insert(bad_reservation);

    let msg = create_discover(
        MacAddr6::new([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]),
        0x66666666,
    );

    let reply = handle_message(&reservations, &leases, &config, &msg);

    assert!(
        matches!(reply, DhcpV4Response::NoResponse(_)),
        "Should not respond when reservation IP not in configured subnet"
    );
}

#[test]
fn mac_has_priority_over_option82() {
    let (config, reservations, leases) = create_test_env();
    // TEST_MAC_2 has both MAC and Option82, MAC should win
    let mut msg = create_discover(TEST_MAC_2, 0x77777777);

    // Add a different Option82 that would match a different reservation
    let mut relay_info = dhcproto::v4::relay::RelayAgentInformation::default();
    relay_info.insert(dhcproto::v4::relay::RelayInfo::AgentRemoteId(
        b"switch1:port1".to_vec(), // This would match the 192.168.1.200 reservation
    ));
    msg.opts_mut()
        .insert(DhcpOption::RelayAgentInformation(relay_info));

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    // Should get the MAC-based reservation (10.10.1.50), not the Option82 one (192.168.1.200)
    assert_eq!(reply.yiaddr(), Ipv4Addr::new(10, 10, 1, 50));
}

// ============================================================================
// REQUEST Tests - SELECTING variant
// ============================================================================

#[test]
fn request_selecting_returns_ack() {
    let (config, reservations, leases) = create_test_env();
    let reserved_ip = Ipv4Addr::new(192, 168, 1, 100);
    let msg = create_request_selecting(TEST_MAC, 0x88888888, config.v4_server_id, reserved_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected ACK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Ack));
    assert_eq!(reply.yiaddr(), reserved_ip);
}

#[test]
fn request_selecting_wrong_server_id_ignored() {
    let (config, reservations, leases) = create_test_env();
    let reserved_ip = Ipv4Addr::new(192, 168, 1, 100);
    let wrong_server = Ipv4Addr::new(10, 0, 0, 99); // Different server
    let msg = create_request_selecting(TEST_MAC, 0x99999999, wrong_server, reserved_ip);

    let reply = handle_message(&reservations, &leases, &config, &msg);

    assert!(
        matches!(reply, DhcpV4Response::NoResponse(_)),
        "Should ignore REQUEST for different server"
    );
}

#[test]
fn request_selecting_wrong_ip_returns_nak() {
    let (config, reservations, leases) = create_test_env();
    let wrong_ip = Ipv4Addr::new(192, 168, 1, 99); // Not the reserved IP
    let msg = create_request_selecting(TEST_MAC, 0xAAAAAAAA, config.v4_server_id, wrong_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected NAK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Nak));
}

// ============================================================================
// REQUEST Tests - INIT-REBOOT variant
// ============================================================================

#[test]
fn request_init_reboot_returns_ack() {
    let (config, reservations, leases) = create_test_env();
    let reserved_ip = Ipv4Addr::new(192, 168, 1, 100);
    let msg = create_request_init_reboot(TEST_MAC, 0xBBBBBBBB, reserved_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected ACK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Ack));
}

#[test]
fn request_init_reboot_wrong_ip_returns_nak() {
    let (config, reservations, leases) = create_test_env();
    let wrong_ip = Ipv4Addr::new(192, 168, 1, 99);
    let msg = create_request_init_reboot(TEST_MAC, 0xCCCCCCCC, wrong_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected NAK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Nak));
}

// ============================================================================
// REQUEST Tests - RENEW variant
// ============================================================================

#[test]
fn request_renew_returns_ack() {
    let (config, reservations, leases) = create_test_env();
    let reserved_ip = Ipv4Addr::new(192, 168, 1, 100);
    let msg = create_request_renew(TEST_MAC, 0xDDDDDDDD, reserved_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected ACK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Ack));
}

// ============================================================================
// REQUEST Tests - REBINDING variant
// ============================================================================

#[test]
fn request_rebinding_returns_ack() {
    let (config, reservations, leases) = create_test_env();
    let reserved_ip = Ipv4Addr::new(192, 168, 1, 100);
    let relay_ip = Ipv4Addr::new(192, 168, 1, 254);
    let msg = create_request_rebinding(TEST_MAC, 0xF0F0F0F0, reserved_ip, relay_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected ACK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Ack));
}

// ============================================================================
// REQUEST Tests - NAK behavior
// ============================================================================

#[test]
fn request_nak_sets_broadcast_flag_when_relayed() {
    let (config, reservations, leases) = create_test_env();
    let wrong_ip = Ipv4Addr::new(192, 168, 1, 99);
    let mut msg = create_request_init_reboot(TEST_MAC, 0xF2F2F2F2, wrong_ip);
    let relay_ip = Ipv4Addr::new(192, 168, 1, 254);
    msg.set_giaddr(relay_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected NAK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Nak));
    // RFC2131: DHCPNAK sent via relay should have broadcast bit set
    assert!(
        Flags::broadcast(&reply.flags()),
        "Broadcast flag should be set for relayed NAK"
    );
}

#[test]
fn request_nak_no_broadcast_when_not_relayed() {
    let (config, reservations, leases) = create_test_env();
    let wrong_ip = Ipv4Addr::new(192, 168, 1, 99);
    let msg = create_request_init_reboot(TEST_MAC, 0xF3F3F3F3, wrong_ip);
    // giaddr is 0 (not relayed)

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected NAK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Nak));
    // Not relayed, so broadcast flag should not be forcibly set
    assert!(
        !Flags::broadcast(&reply.flags()),
        "Broadcast flag should not be set for non-relayed NAK"
    );
}

// ============================================================================
// Opcode handling tests
// ============================================================================

#[test]
fn boot_reply_is_ignored() {
    let (config, reservations, leases) = create_test_env();
    let mut msg = create_discover(TEST_MAC, 0xF4F4F4F4);
    msg.set_opcode(Opcode::BootReply); // Server should ignore BootReply

    let reply = handle_message(&reservations, &leases, &config, &msg);

    assert!(
        matches!(reply, DhcpV4Response::NoResponse(_)),
        "Server should ignore BootReply messages"
    );
}

#[test]
fn unknown_opcode_is_ignored() {
    let (config, reservations, leases) = create_test_env();
    let mut msg = create_discover(TEST_MAC, 0xF5F5F5F5);
    msg.set_opcode(Opcode::Unknown(99));

    let reply = handle_message(&reservations, &leases, &config, &msg);

    assert!(
        matches!(reply, DhcpV4Response::NoResponse(_)),
        "Server should ignore unknown opcodes"
    );
}

// ============================================================================
// Option82 binding tests (for IPv6 fallback)
// ============================================================================

#[test]
fn option82_binding_created_on_ack() {
    let (config, reservations, leases) = create_test_env();

    // Use a MAC that doesn't have a direct reservation
    let client_mac = MacAddr6::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    // But the Option82 matches the reservation for 192.168.1.200
    let mut msg = create_request_selecting(
        client_mac,
        0xF6F6F6F6,
        config.v4_server_id,
        Ipv4Addr::new(192, 168, 1, 200),
    );

    let mut relay_info = dhcproto::v4::relay::RelayAgentInformation::default();
    relay_info.insert(dhcproto::v4::relay::RelayInfo::AgentRemoteId(
        b"switch1:port1".to_vec(),
    ));
    msg.opts_mut()
        .insert(DhcpOption::RelayAgentInformation(relay_info));

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected ACK, got NoResponse({:?})", reason),
    };
    assert_eq!(reply.message_type(), Some(&v4::MessageType::Ack));

    // Now check that the MAC→Option82 binding was created in the lease database
    let opt82 = leases.get_opt82_by_mac(&client_mac);
    assert!(opt82.is_some(), "Option82 binding should be created on ACK");
    let opt82 = opt82.unwrap();
    assert_eq!(opt82.remote.as_deref(), Some("switch1:port1"));
}

// ============================================================================
// Response format tests
// ============================================================================

#[test]
fn response_opcode_is_boot_reply() {
    let (config, reservations, leases) = create_test_env();
    let msg = create_discover(TEST_MAC, 0xF7F7F7F7);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    assert_eq!(reply.opcode(), Opcode::BootReply);
}

#[test]
fn response_preserves_flags() {
    let (config, reservations, leases) = create_test_env();
    let mut msg = create_discover(TEST_MAC, 0xF8F8F8F8);
    msg.set_flags(Flags::set_broadcast(msg.flags())); // Client requests broadcast

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    assert!(
        Flags::broadcast(&reply.flags()),
        "Should preserve client's broadcast flag"
    );
}

// ============================================================================
// RFC 2131 Compliance Tests - These test for potential protocol bugs
// ============================================================================

/// RFC 2131 Table 3: DHCPNAK MUST have yiaddr = 0
/// BUG: Current implementation leaves yiaddr set to reservation.ipv4 when sending NAK
#[test]
fn nak_yiaddr_must_be_zero() {
    let (config, reservations, leases) = create_test_env();
    let wrong_ip = Ipv4Addr::new(192, 168, 1, 99); // Not the reserved IP
    let msg = create_request_selecting(TEST_MAC, 0x11112222, config.v4_server_id, wrong_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected NAK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Nak));
    // RFC 2131 Table 3: yiaddr in DHCPNAK MUST be 0
    assert_eq!(
        reply.yiaddr(),
        Ipv4Addr::UNSPECIFIED,
        "RFC 2131: DHCPNAK yiaddr MUST be 0, but got {}",
        reply.yiaddr()
    );
}

/// RFC 2131 Section 4.3.2 and Table 3: In RENEW/REBINDING ACK, yiaddr MUST be
/// set to the assigned IP address, not 0.
#[test]
fn renew_ack_yiaddr_must_be_set() {
    let (config, reservations, leases) = create_test_env();
    let reserved_ip = Ipv4Addr::new(192, 168, 1, 100);
    let msg = create_request_renew(TEST_MAC, 0x33334444, reserved_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected ACK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Ack));
    // RFC 2131 Table 3: yiaddr in DHCPACK = "IP address assigned to client"
    // Even in RENEW, the server should confirm the assigned address
    assert_eq!(
        reply.yiaddr(),
        reserved_ip,
        "RFC 2131: DHCPACK yiaddr MUST be the assigned IP, but got {} (expected {})",
        reply.yiaddr(),
        reserved_ip
    );
}

/// RFC 2131: Same as above but for REBINDING variant
#[test]
fn rebinding_ack_yiaddr_must_be_set() {
    let (config, reservations, leases) = create_test_env();
    let reserved_ip = Ipv4Addr::new(192, 168, 1, 100);
    let relay_ip = Ipv4Addr::new(192, 168, 1, 254);
    let msg = create_request_rebinding(TEST_MAC, 0x55556666, reserved_ip, relay_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected ACK, got NoResponse({:?})", reason),
    };

    assert_eq!(reply.message_type(), Some(&v4::MessageType::Ack));
    assert_eq!(
        reply.yiaddr(),
        reserved_ip,
        "RFC 2131: DHCPACK yiaddr MUST be the assigned IP in REBINDING, but got {}",
        reply.yiaddr()
    );
}

/// RFC 2131: T1 (renewal time, option 58) SHOULD be included
#[test]
fn ack_should_include_t1_renewal_time_t2_rebinding_time() {
    let (config, reservations, leases) = create_test_env();
    let reserved_ip = Ipv4Addr::new(192, 168, 1, 100);
    let msg = create_request_selecting(TEST_MAC, 0x77778888, config.v4_server_id, reserved_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected ACK, got NoResponse({:?})", reason),
    };

    let has_t1 = reply
        .opts()
        .iter()
        .any(|(_, opt)| matches!(opt, DhcpOption::Renewal(t1) if *t1 == RENEWAL_TIME));
    assert!(
        has_t1,
        "RFC 2131: DHCPACK SHOULD include T1 (Renewal Time = {})",
        RENEWAL_TIME
    );
    let has_t2 = reply
        .opts()
        .iter()
        .any(|(_, opt)| matches!(opt, DhcpOption::Rebinding(t2) if *t2 == REBINDING_TIME));
    assert!(
        has_t2,
        "RFC 2131: DHCPACK SHOULD include T2 (Rebinding Time = {})",
        REBINDING_TIME
    );
}

/// RFC 2131 Section 4.3.2: In INIT-REBOOT, if server has no record of client,
/// it MUST remain silent (not send NAK).
/// This tests the boundary case where we have a reservation but client requests
/// an IP that's on a completely wrong subnet.
#[test]
fn init_reboot_wrong_subnet_should_nak() {
    let (config, reservations, leases) = create_test_env();
    // Client requests an IP on a completely different subnet
    let wrong_subnet_ip = Ipv4Addr::new(172, 16, 0, 100);
    let msg = create_request_init_reboot(TEST_MAC, 0xBBBBCCCC, wrong_subnet_ip);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => panic!("Expected NAK, got NoResponse({:?})", reason),
    };

    // RFC 2131: "Server SHOULD send a DHCPNAK message to the client if the
    // 'requested IP address' is incorrect, or is on the wrong network."
    assert_eq!(reply.message_type(), Some(&v4::MessageType::Nak));
}

/// RFC 2131: OFFER should also include T1/T2 so client knows renewal schedule
#[test]
fn offer_should_include_t1_renewal_time() {
    let (config, reservations, leases) = create_test_env();
    let msg = create_discover(TEST_MAC, 0xDDDDEEEE);

    let reply = match handle_message(&reservations, &leases, &config, &msg) {
        DhcpV4Response::Message(resp) => resp.message,
        DhcpV4Response::NoResponse(reason) => {
            panic!("Expected OFFER, got NoResponse({:?})", reason)
        }
    };

    let has_t1 = reply
        .opts()
        .iter()
        .any(|(_, opt)| matches!(opt, DhcpOption::Renewal(t1) if *t1 == RENEWAL_TIME));
    assert!(
        has_t1,
        "DHCPOFFER SHOULD include T1 (Renewal Time = {})",
        RENEWAL_TIME
    );
    let has_t2 = reply
        .opts()
        .iter()
        .any(|(_, opt)| matches!(opt, DhcpOption::Rebinding(t2) if *t2 == REBINDING_TIME));
    assert!(
        has_t2,
        "DHCPOFFER SHOULD include T2 (Rebinding Time = {})",
        REBINDING_TIME
    );
}
