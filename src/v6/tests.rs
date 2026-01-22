#![cfg(test)]

use advmac::MacAddr6;
use dhcproto::{
    v6::{
        ClientLinklayerAddress, DhcpOption, DhcpOptions, IAAddr, IAPrefix, Message, MessageType,
        RelayMessage, RelayMessageData, IANA, IAPD,
    },
    Decodable,
};
use ipnet::Ipv6Net;
use shadowdhcp::{Duid, Option82, Reservation, V4Subnet};

use crate::config::Config;
use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;
use crate::v6::extractors as v6_extractors;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::v6::{
    extensions::ShadowMessageExtV6, handlers::DhcpV6Response, PREFERRED_LIFETIME, REBINDING_TIME,
    RENEWAL_TIME, VALID_LIFETIME,
};

const RESERVATION_MAC: MacAddr6 = MacAddr6::new([0, 1, 2, 3, 4, 5]);

fn create_env() -> (Config, ReservationDb, LeaseDb) {
    let config = Config {
        v4_server_id: Ipv4Addr::new(1, 1, 1, 1),
        subnets_v4: vec![V4Subnet {
            net: "192.168.0.0/24".parse().unwrap(),
            gateway: "192.168.0.1".parse().unwrap(),
            reply_prefix_len: None,
        }],
        v6_server_id: Duid::from(vec![0, 1, 2, 3]),
        option1837_extractors: v6_extractors::get_all_extractors().into_iter().collect(),
        ..Default::default()
    };

    let reservation = Reservation {
        ipv4: Ipv4Addr::new(192, 168, 0, 10),
        ipv6_na: "2001:db8::1".parse().unwrap(),
        ipv6_pd: "2001:db8:100::/56".parse::<Ipv6Net>().unwrap(),
        mac: Some(RESERVATION_MAC),
        duid: Some(Duid::from(vec![0xaa, 0xbb, 0xcc])),
        option82: None,
        option1837: None,
    };

    let reservations = ReservationDb::new();
    reservations.insert(reservation.clone());

    let leases = LeaseDb::new();

    (config, reservations, leases)
}

fn create_relay_forw(msg: &dhcproto::v6::Message) -> RelayMessage {
    let mut relay_opts = DhcpOptions::new();
    relay_opts.insert(DhcpOption::RelayMsg(RelayMessageData::Message(msg.clone())));

    RelayMessage {
        msg_type: MessageType::RelayForw,
        hop_count: 0,
        link_addr: Ipv6Addr::UNSPECIFIED,
        peer_addr: Ipv6Addr::UNSPECIFIED,
        opts: relay_opts,
    }
}

// Generated with GPT-5.2 instant
#[test]
fn request_echoes_iaid() {
    let (config, reservations, leases) = create_env();

    let ia_na_iaid = 314u32;
    let ia_pd_iaid = 2718u32;

    let reservation = reservations
        .by_mac(RESERVATION_MAC)
        .expect("No reservation found");

    let mut msg = Message::new(MessageType::Request);
    let opts = msg.opts_mut();

    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));
    opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));

    opts.insert(DhcpOption::IANA(IANA {
        id: ia_na_iaid,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAAddr(IAAddr {
                addr: reservation.ipv6_na,
                preferred_life: 100,
                valid_life: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    opts.insert(DhcpOption::IAPD(IAPD {
        id: ia_pd_iaid,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAPrefix(IAPrefix {
                prefix_ip: reservation.ipv6_pd.addr(),
                prefix_len: reservation.ipv6_pd.prefix_len(),
                preferred_lifetime: 100,
                valid_lifetime: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        crate::v6::handlers::DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply"),
    };

    assert!(matches!(resp.msg_type(), MessageType::Reply));

    let returned_iana = resp.ia_na().unwrap();
    let returned_iapd = resp.ia_pd().unwrap();
    assert_eq!(
        returned_iana.id, ia_na_iaid,
        "IA_NA IAID not echoed in Request reply"
    );
    assert_eq!(
        returned_iapd.id, ia_pd_iaid,
        "IA_PD IAID not echoed in Request reply"
    );
}

// Generated with GPT-5.2 instant
#[test]
fn solicit_advertise_echoes_iaid() {
    let (config, reservations, leases) = create_env();

    let ia_na_iaid = 123u32;
    let ia_pd_iaid = 456u32;

    let mut msg = Message::new(MessageType::Solicit);
    let opts = msg.opts_mut();

    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));

    opts.insert(DhcpOption::IANA(IANA {
        id: ia_na_iaid,
        t1: 0,
        t2: 0,
        opts: DhcpOptions::new(),
    }));

    opts.insert(DhcpOption::IAPD(IAPD {
        id: ia_pd_iaid,
        t1: 0,
        t2: 0,
        opts: DhcpOptions::new(),
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        crate::v6::handlers::DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Advertise"),
    };

    let returned_iana = resp.ia_na().unwrap();
    let returned_iapd = resp.ia_pd().unwrap();

    assert_eq!(returned_iana.id, ia_na_iaid, "IA_NA IAID not echoed");
    assert_eq!(returned_iapd.id, ia_pd_iaid, "IA_PD IAID not echoed");
}

// Generated with GPT-5.2 instant
#[test]
fn renew_echoes_iaid() {
    let (config, reservations, leases) = create_env();

    let ia_na_iaid = 42u32;
    let ia_pd_iaid = 1337u32;

    let mut msg = Message::new(MessageType::Renew);
    let opts = msg.opts_mut();

    let reservation = reservations
        .by_mac(RESERVATION_MAC)
        .expect("No reservation found");

    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));
    opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));

    opts.insert(DhcpOption::IANA(IANA {
        id: ia_na_iaid,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAAddr(IAAddr {
                addr: reservation.ipv6_na,
                preferred_life: 100,
                valid_life: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    opts.insert(DhcpOption::IAPD(IAPD {
        id: ia_pd_iaid,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAPrefix(IAPrefix {
                prefix_ip: reservation.ipv6_pd.addr(),
                prefix_len: reservation.ipv6_pd.prefix_len(),
                preferred_lifetime: 100,
                valid_lifetime: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        crate::v6::handlers::DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply"),
    };

    let returned_iana = resp.ia_na().unwrap();

    let returned_iapd = resp.ia_pd().unwrap();
    assert_eq!(returned_iana.id, ia_na_iaid);
    assert_eq!(returned_iapd.id, ia_pd_iaid);
}

// Generated with GPT-5.2 instant
#[test]
fn renew_with_incorrect_iana_address_returns_reserved_address() {
    let (config, reservations, leases) = create_env();

    let ia_na_iaid = 777u32;

    let reservation = reservations
        .by_mac(RESERVATION_MAC)
        .expect("No reservation found");

    let incorrect_addr: Ipv6Addr = "2001:db8::dead".parse().unwrap();
    assert_ne!(
        incorrect_addr, reservation.ipv6_na,
        "Test setup error: incorrect address matches reservation"
    );

    let mut msg = Message::new(MessageType::Renew);
    let opts = msg.opts_mut();

    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));
    opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));

    // Client sends IA_NA with WRONG address
    opts.insert(DhcpOption::IANA(IANA {
        id: ia_na_iaid,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAAddr(IAAddr {
                addr: incorrect_addr,
                preferred_life: 100,
                valid_life: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        crate::v6::handlers::DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply"),
    };

    assert!(matches!(resp.msg_type(), MessageType::Reply));

    let returned_iana = resp.ia_na().expect("Reply missing IANA");
    assert_eq!(
        returned_iana.id, ia_na_iaid,
        "IAID must be echoed even on incorrect address"
    );

    let returned_addr = resp.ia_na_address().expect("Returned IANA missing IAAddr");
    assert_eq!(
        returned_addr, reservation.ipv6_na,
        "Server must return reserved IPv6 address, not the incorrect one"
    );
}

// Generated with GPT-5.2 instant
#[test]
fn renew_no_reservation_returns_no_binding() {
    let (config, reservations, leases) = create_env();

    let mut msg = Message::new(MessageType::Renew);
    let opts = msg.opts_mut();

    opts.insert(DhcpOption::ClientId(vec![0xde, 0xad, 0xbe, 0xff]));
    opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));

    opts.insert(DhcpOption::IANA(IANA {
        id: 1,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAAddr(IAAddr {
                addr: "2001:db8::1234".parse().unwrap(),
                preferred_life: 100,
                valid_life: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        crate::v6::handlers::DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply"),
    };

    let message_level_status = resp
        .opts()
        .iter()
        .find(|opt| matches!(opt, DhcpOption::StatusCode(_)));
    assert!(
        message_level_status.is_none(),
        "StatusCode should NOT be at message level per RFC 8415"
    );

    let returned_iana = resp.ia_na().expect("Reply missing IANA");

    let returned_addr = returned_iana
        .opts
        .iter()
        .find_map(|opt| match opt {
            DhcpOption::IAAddr(addr) => Some(addr),
            _ => None,
        })
        .expect("Returned IANA missing IAAddr");

    assert_eq!(returned_addr.preferred_life, 0);
    assert_eq!(returned_addr.valid_life, 0);

    // Verify StatusCode is inside the IA_NA option
    let ia_status = returned_iana
        .opts
        .iter()
        .find_map(|opt| match opt {
            DhcpOption::StatusCode(code) => Some(code),
            _ => None,
        })
        .expect("IA_NA missing StatusCode - should be inside IA per RFC 8415");
    assert_eq!(ia_status.status, dhcproto::v6::Status::NoBinding);
}

/// RFC 8415 Section 18.4.2: Verify NoBinding status is inside IA_PD option too
#[test]
fn renew_no_reservation_returns_no_binding_in_iapd() {
    let (config, reservations, leases) = create_env();

    let mut msg = Message::new(MessageType::Renew);
    let opts = msg.opts_mut();

    opts.insert(DhcpOption::ClientId(vec![0xde, 0xad, 0xbe, 0xff]));
    opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));

    opts.insert(DhcpOption::IAPD(IAPD {
        id: 1,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAPrefix(IAPrefix {
                prefix_ip: "2001:db8:abcd::".parse().unwrap(),
                prefix_len: 56,
                preferred_lifetime: 100,
                valid_lifetime: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply"),
    };

    // Verify no message-level StatusCode
    let message_level_status = resp
        .opts()
        .iter()
        .find(|opt| matches!(opt, DhcpOption::StatusCode(_)));
    assert!(
        message_level_status.is_none(),
        "StatusCode should NOT be at message level per RFC 8415"
    );

    let returned_iapd = resp.ia_pd().expect("Reply missing IA_PD");

    // Verify lifetimes are zeroed
    let returned_prefix = returned_iapd
        .opts
        .iter()
        .find_map(|opt| match opt {
            DhcpOption::IAPrefix(prefix) => Some(prefix),
            _ => None,
        })
        .expect("Returned IA_PD missing IAPrefix");

    assert_eq!(returned_prefix.preferred_lifetime, 0);
    assert_eq!(returned_prefix.valid_lifetime, 0);

    // Verify StatusCode is inside the IA_PD option
    let ia_status = returned_iapd
        .opts
        .iter()
        .find_map(|opt| match opt {
            DhcpOption::StatusCode(code) => Some(code),
            _ => None,
        })
        .expect("IA_PD missing StatusCode - should be inside IA per RFC 8415");
    assert_eq!(ia_status.status, dhcproto::v6::Status::NoBinding);
}

// Generated with GPT-5.2 instant
#[test]
fn renew_with_incorrect_iana_and_iapd_returns_reserved_values() {
    let (config, reservations, leases) = create_env();

    let reservation = reservations
        .by_mac(RESERVATION_MAC)
        .expect("No reservation found");

    let wrong_na: Ipv6Addr = "2001:db8::beef".parse().unwrap();
    let wrong_pd: Ipv6Net = "2001:db8:ffff::/56".parse().unwrap();

    let mut msg = Message::new(MessageType::Renew);
    let opts = msg.opts_mut();

    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));
    opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));

    opts.insert(DhcpOption::IANA(IANA {
        id: 10,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAAddr(IAAddr {
                addr: wrong_na,
                preferred_life: 100,
                valid_life: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    opts.insert(DhcpOption::IAPD(IAPD {
        id: 20,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAPrefix(IAPrefix {
                prefix_ip: wrong_pd.addr(),
                prefix_len: wrong_pd.prefix_len(),
                preferred_lifetime: 100,
                valid_lifetime: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        crate::v6::handlers::DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply"),
    };

    assert!(matches!(resp.msg_type(), MessageType::Reply));

    let returned_iana = resp.ia_na().expect("Reply missing IANA");
    let returned_iapd = resp.ia_pd().expect("Reply missing IAPD");
    let returned_na = resp.ia_na_address().unwrap();
    let returned_pd = resp.ia_pd_prefix().unwrap();

    assert_eq!(returned_na, reservation.ipv6_na);
    assert_eq!(returned_pd, reservation.ipv6_pd);
    assert_eq!(returned_iana.id, 10);
    assert_eq!(returned_iapd.id, 20);
}

#[test]
fn reply_test() {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::RelayMsg(RelayMessageData::Message(
        Message::new(MessageType::Solicit),
    )));

    let reply = RelayMessage {
        msg_type: MessageType::RelayForw,
        hop_count: 0,
        link_addr: Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
        peer_addr: Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 9),
        opts,
    };

    println!("{reply:?}");
}

#[test]
fn mikrotik_solicit() {
    let packet_bytes: [u8; 66] = [
        0x01, 0xa4, 0xcf, 0x70, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55, 0x31,
        0x8f, 0x19, 0x94, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x07, 0x08,
        0x00, 0x00, 0x0b, 0x40, 0x00, 0x06, 0x00, 0x02, 0x00, 0x17, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
        0x07, 0x08, 0x00, 0x00, 0x0b, 0x40,
    ];

    let msg = Message::from_bytes(&packet_bytes).unwrap();
    assert!(matches!(msg.msg_type(), MessageType::Solicit));
    assert!(msg.ia_na().is_some());
    assert!(msg.ia_pd().is_some());
    assert_eq!(msg.xid(), [164, 207, 112]);
}

#[test]
fn kea_advertise() {
    let packet_bytes: [u8; 125] = [
        0x02, 0xa4, 0xcf, 0x70, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55, 0x31,
        0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x2d, 0xf2, 0x39, 0xc7,
        0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03, 0x00, 0x28, 0x00, 0x00, 0x00, 0x05, 0x00,
        0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0xcb, 0x40,
        0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b,
        0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x19, 0x00, 0x29, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
        0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8, 0x00,
        0x00, 0x0f, 0xa0, 0x38, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let msg = Message::from_bytes(&packet_bytes).unwrap();
    assert!(matches!(msg.msg_type(), MessageType::Advertise));
    assert!(msg.ia_na().is_some());
    assert!(msg.ia_pd().is_some());
    assert_eq!(msg.xid(), [164, 207, 112]);
}

#[test]
fn mikrotik_request() {
    let packet_bytes: [u8; 137] = [
        0x03, 0x2a, 0xcb, 0x85, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55, 0x31,
        0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x2d, 0xf2, 0x39, 0xc7,
        0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03, 0x00, 0x28, 0x00, 0x00, 0x00, 0x05, 0x00,
        0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0xcb, 0x40,
        0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b,
        0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x06, 0x00, 0x02, 0x00, 0x17, 0x00, 0x08, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x19, 0x00, 0x29, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00,
        0x00, 0x07, 0xd0, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0,
        0x38, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let msg = Message::from_bytes(&packet_bytes).unwrap();
    assert!(matches!(msg.msg_type(), MessageType::Request));
    assert_eq!(msg.xid(), [42, 203, 133]);
}

#[test]
fn kea_reply() {
    let packet_bytes: [u8; 125] = [
        0x07, 0x2a, 0xcb, 0x85, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55, 0x31,
        0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x2d, 0xf2, 0x39, 0xc7,
        0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03, 0x00, 0x28, 0x00, 0x00, 0x00, 0x05, 0x00,
        0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0xcb, 0x40,
        0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b,
        0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x19, 0x00, 0x29, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
        0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8, 0x00,
        0x00, 0x0f, 0xa0, 0x38, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let msg = Message::from_bytes(&packet_bytes).unwrap();
    assert!(matches!(msg.msg_type(), MessageType::Reply));
    assert_eq!(msg.xid(), [42, 203, 133]);
}

#[test]
fn mikrotik_relay_forw_solicit_to_server() {
    let packet_bytes: [u8; 124] = [
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x55, 0x31, 0xff,
        0xfe, 0x8f, 0x19, 0x98, 0x00, 0x4f, 0x00, 0x08, 0x00, 0x01, 0x0a, 0x55, 0x31, 0x8f, 0x19,
        0x98, 0x00, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x09, 0x00, 0x42, 0x01, 0x9c,
        0x31, 0xb2, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55, 0x31, 0x8f, 0x19,
        0x94, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00,
        0x0b, 0x40, 0x00, 0x06, 0x00, 0x02, 0x00, 0x17, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x0e, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x07, 0x08,
        0x00, 0x00, 0x0b, 0x40,
    ];

    let msg = RelayMessage::from_bytes(&packet_bytes).unwrap();
    assert!(matches!(msg.msg_type, MessageType::RelayForw));
    println!("{msg:?}");
}

#[test]
fn mikrotik_relay_reply_server_advertise_to_client() {
    let packet_bytes: [u8; 171] = [
        0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x55, 0x31, 0xff,
        0xfe, 0x8f, 0x19, 0x98, 0x00, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x09, 0x00,
        0x7d, 0x02, 0x9c, 0x31, 0xb2, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55,
        0x31, 0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x2d, 0xf2, 0x39,
        0xc7, 0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03, 0x00, 0x28, 0x00, 0x00, 0x00, 0x05,
        0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0xcb,
        0x40, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x19, 0x00, 0x29, 0x00, 0x00, 0x00, 0x05, 0x00,
        0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8,
        0x00, 0x00, 0x0f, 0xa0, 0x38, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let msg = RelayMessage::from_bytes(&packet_bytes).unwrap();
    assert!(matches!(msg.msg_type, MessageType::RelayRepl));
    println!("{msg:?}");
}

#[test]
fn mikrotik_relay_forw_request_to_server() {
    let packet_bytes: [u8; 195] = [
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x55, 0x31, 0xff,
        0xfe, 0x8f, 0x19, 0x98, 0x00, 0x4f, 0x00, 0x08, 0x00, 0x01, 0x0a, 0x55, 0x31, 0x8f, 0x19,
        0x98, 0x00, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x09, 0x00, 0x89, 0x03, 0xcb,
        0x9e, 0x48, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55, 0x31, 0x8f, 0x19,
        0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x2d, 0xf2, 0x39, 0xc7, 0xbc, 0x24,
        0x11, 0xa7, 0x20, 0x34, 0x00, 0x03, 0x00, 0x28, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03,
        0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b, 0xb8, 0x00,
        0x00, 0x0f, 0xa0, 0x00, 0x06, 0x00, 0x02, 0x00, 0x17, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x19, 0x00, 0x29, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07,
        0xd0, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x38, 0x26,
        0x05, 0xcb, 0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let msg = RelayMessage::from_bytes(&packet_bytes).unwrap();
    assert!(matches!(msg.msg_type, MessageType::RelayForw));

    let link_layer_addr = msg
        .opts()
        .iter()
        .find_map(|opt| match opt {
            DhcpOption::ClientLinklayerAddress(ll) => Some(ll),
            _ => None,
        })
        .unwrap();
    println!("{link_layer_addr:?}");
    println!("{msg:?}");
}

#[test]
fn mikrotik_relay_reply_server_reply_to_client() {
    let packet_bytes: [u8; 171] = [
        0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x55, 0x31, 0xff,
        0xfe, 0x8f, 0x19, 0x98, 0x00, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x09, 0x00,
        0x7d, 0x07, 0xcb, 0x9e, 0x48, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55,
        0x31, 0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x2d, 0xf2, 0x39,
        0xc7, 0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03, 0x00, 0x28, 0x00, 0x00, 0x00, 0x05,
        0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0xcb,
        0x40, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x19, 0x00, 0x29, 0x00, 0x00, 0x00, 0x05, 0x00,
        0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8,
        0x00, 0x00, 0x0f, 0xa0, 0x38, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let msg = RelayMessage::from_bytes(&packet_bytes).unwrap();
    assert!(matches!(msg.msg_type, MessageType::RelayRepl));
    println!("{msg:?}");
}

#[test]
fn dynamic_opt82_binding() {
    let json_str = r#"
    [
        {
            "ipv4": "192.168.1.111",
            "ipv6_na": "2001:db8:1:6::1",
            "ipv6_pd": "2001:db8:1:7::/56",
            "option82": {"circuit": "99-11-22-33-44-55", "remote": "eth2:100"}
        },
        {
            "ipv4": "192.168.1.112",
            "ipv6_na": "2001:db8:1:8::1",
            "ipv6_pd": "2001:db8:1:9::/56",
            "duid": "00:11:22:33:44:55:66",
            "option82": {"subscriber": "subscriber:1020"}
        }
    ]
    "#;
    let reservations: Vec<Reservation> = serde_json::from_str(json_str).unwrap();
    let db = ReservationDb::new();
    db.load_reservations(reservations);
    let leases = LeaseDb::new();
    let opt82 = Option82 {
        circuit: Some("99-11-22-33-44-55".into()),
        remote: Some("eth2:100".into()),
        subscriber: None,
    };
    let mac = MacAddr6::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    leases.insert_mac_option82_binding(&mac, &opt82);

    let duid = vec![0x00, 0x01];
    let mut msg = Message::new(MessageType::Solicit);
    let msg_opts = msg.opts_mut();
    msg_opts.insert(DhcpOption::ClientId(duid));
    msg_opts.insert(DhcpOption::IANA(IANA {
        id: 1,
        t1: 100,
        t2: 1000,
        opts: DhcpOptions::new(),
    }));
    msg_opts.insert(DhcpOption::IAPD(IAPD {
        id: 1,
        t1: 100,
        t2: 1000,
        opts: DhcpOptions::new(),
    }));

    // pack msg into a relay_msg
    let mut relay_opts = DhcpOptions::new();
    relay_opts.insert(DhcpOption::RelayMsg(RelayMessageData::Message(msg.clone())));
    relay_opts.insert(DhcpOption::ClientLinklayerAddress(ClientLinklayerAddress {
        address_type: 1,
        address: mac.to_array().to_vec(),
    }));

    let relay_msg = RelayMessage {
        msg_type: MessageType::RelayForw,
        hop_count: 0,
        link_addr: Ipv6Addr::new(8, 8, 8, 8, 8, 8, 8, 8),
        peer_addr: Ipv6Addr::new(9, 9, 9, 9, 9, 9, 9, 9),
        opts: relay_opts,
    };

    let (config, _, _) = create_env();
    let resp = match crate::v6::handlers::handle_message(&config, &db, &leases, &msg, &relay_msg) {
        DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected message response"),
    };
    assert!(matches!(resp.msg_type(), MessageType::Advertise));

    let reservation = db.by_opt82(&opt82).unwrap();
    assert_eq!(resp.ia_na_address().unwrap(), reservation.ipv6_na);
    assert_eq!(resp.ia_pd_prefix().unwrap(), reservation.ipv6_pd);
}

/// RFC 8415 Section 21.8: Advertise messages should include Preference option
#[test]
fn advertise_includes_preference_option() {
    let (config, reservations, leases) = create_env();

    let mut msg = Message::new(MessageType::Solicit);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));
    opts.insert(DhcpOption::IANA(IANA {
        id: 1,
        t1: 0,
        t2: 0,
        opts: DhcpOptions::new(),
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Advertise response"),
    };

    assert!(matches!(resp.msg_type(), MessageType::Advertise));

    // Verify Preference option is included
    let preference = resp
        .opts()
        .iter()
        .find_map(|opt| match opt {
            DhcpOption::Preference(pref) => Some(*pref),
            _ => None,
        })
        .expect("Advertise should include Preference option per RFC 8415");

    assert_eq!(preference, 255, "Preference should be 255 (maximum)");
}

/// RFC 8415: Reply messages (rapid commit) should NOT include Preference option
#[test]
fn rapid_commit_reply_does_not_include_preference() {
    let (config, reservations, leases) = create_env();

    let mut msg = Message::new(MessageType::Solicit);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));
    opts.insert(DhcpOption::RapidCommit); // Request rapid commit
    opts.insert(DhcpOption::IANA(IANA {
        id: 1,
        t1: 0,
        t2: 0,
        opts: DhcpOptions::new(),
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply response"),
    };

    assert!(matches!(resp.msg_type(), MessageType::Reply));

    // Verify Preference option is NOT included in Reply (only in Advertise)
    let preference = resp
        .opts()
        .iter()
        .find(|opt| matches!(opt, DhcpOption::Preference(_)));
    assert!(
        preference.is_none(),
        "Reply should NOT include Preference option"
    );

    // But it should include RapidCommit
    let rapid_commit = resp
        .opts()
        .iter()
        .find(|opt| matches!(opt, DhcpOption::RapidCommit));
    assert!(
        rapid_commit.is_some(),
        "Reply should include RapidCommit option"
    );
}

/// RFC 8415 Section 21.4, 21.21: T1 and T2 must be less than preferred lifetime
/// T1 = 0.5 * preferred_lifetime (RENEWAL_TIME)
/// T2 = 0.8 * preferred_lifetime (REBINDING_TIME)
#[test]
fn t1_t2_constants_are_rfc_compliant() {
    // T1 should be 0.5 * preferred_lifetime
    assert_eq!(RENEWAL_TIME, PREFERRED_LIFETIME / 2);
    assert_eq!(RENEWAL_TIME, 1800);

    // T2 should be 0.8 * preferred_lifetime
    assert_eq!(REBINDING_TIME, PREFERRED_LIFETIME * 4 / 5);
    assert_eq!(REBINDING_TIME, 2880);

    // RFC 8415: T1 < T2 < preferred_lifetime < valid_lifetime
    assert!(RENEWAL_TIME < REBINDING_TIME);
    assert!(REBINDING_TIME < PREFERRED_LIFETIME);
    assert!(PREFERRED_LIFETIME < VALID_LIFETIME);
}

/// Verify that Solicit response contains correct T1/T2 values per RFC 8415
#[test]
fn solicit_response_has_correct_t1_t2() {
    let (config, reservations, leases) = create_env();

    let mut msg = Message::new(MessageType::Solicit);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));
    opts.insert(DhcpOption::IANA(IANA {
        id: 1,
        t1: 0,
        t2: 0,
        opts: DhcpOptions::new(),
    }));
    opts.insert(DhcpOption::IAPD(IAPD {
        id: 2,
        t1: 0,
        t2: 0,
        opts: DhcpOptions::new(),
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Advertise response"),
    };

    let iana = resp.ia_na().expect("Response missing IA_NA");
    let iapd = resp.ia_pd().expect("Response missing IA_PD");

    // Verify T1 and T2 are set correctly per RFC 8415
    assert_eq!(iana.t1, RENEWAL_TIME, "IA_NA T1 should be RENEWAL_TIME");
    assert_eq!(iana.t2, REBINDING_TIME, "IA_NA T2 should be REBINDING_TIME");
    assert_eq!(iapd.t1, RENEWAL_TIME, "IA_PD T1 should be RENEWAL_TIME");
    assert_eq!(iapd.t2, REBINDING_TIME, "IA_PD T2 should be REBINDING_TIME");

    // Verify preferred and valid lifetimes in nested options
    let ia_addr = iana
        .opts
        .iter()
        .find_map(|o| match o {
            DhcpOption::IAAddr(addr) => Some(addr),
            _ => None,
        })
        .expect("IA_NA missing IAAddr");
    assert_eq!(ia_addr.preferred_life, PREFERRED_LIFETIME);
    assert_eq!(ia_addr.valid_life, VALID_LIFETIME);

    let ia_prefix = iapd
        .opts
        .iter()
        .find_map(|o| match o {
            DhcpOption::IAPrefix(prefix) => Some(prefix),
            _ => None,
        })
        .expect("IA_PD missing IAPrefix");
    assert_eq!(ia_prefix.preferred_lifetime, PREFERRED_LIFETIME);
    assert_eq!(ia_prefix.valid_lifetime, VALID_LIFETIME);
}

/// Verify that Request response contains correct T1/T2 values per RFC 8415
#[test]
fn request_response_has_correct_t1_t2() {
    let (config, reservations, leases) = create_env();

    let mut msg = Message::new(MessageType::Request);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));
    opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));
    opts.insert(DhcpOption::IANA(IANA {
        id: 1,
        t1: 0,
        t2: 0,
        opts: DhcpOptions::new(),
    }));
    opts.insert(DhcpOption::IAPD(IAPD {
        id: 2,
        t1: 0,
        t2: 0,
        opts: DhcpOptions::new(),
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply response"),
    };

    let iana = resp.ia_na().expect("Response missing IA_NA");
    let iapd = resp.ia_pd().expect("Response missing IA_PD");

    assert_eq!(iana.t1, RENEWAL_TIME, "IA_NA T1 should be RENEWAL_TIME");
    assert_eq!(iana.t2, REBINDING_TIME, "IA_NA T2 should be REBINDING_TIME");
    assert_eq!(iapd.t1, RENEWAL_TIME, "IA_PD T1 should be RENEWAL_TIME");
    assert_eq!(iapd.t2, REBINDING_TIME, "IA_PD T2 should be REBINDING_TIME");
}

/// RFC 8415 Section 18.4.5: Rebind works without Server ID (unlike Renew)
#[test]
fn rebind_works_without_server_id() {
    let (config, reservations, leases) = create_env();

    let reservation = reservations
        .by_mac(RESERVATION_MAC)
        .expect("No reservation found");

    let mut msg = Message::new(MessageType::Rebind);
    let opts = msg.opts_mut();
    // Rebind only requires Client ID, NOT Server ID
    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));
    opts.insert(DhcpOption::IANA(IANA {
        id: 1,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAAddr(IAAddr {
                addr: reservation.ipv6_na,
                preferred_life: 100,
                valid_life: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));
    opts.insert(DhcpOption::IAPD(IAPD {
        id: 2,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAPrefix(IAPrefix {
                prefix_ip: reservation.ipv6_pd.addr(),
                prefix_len: reservation.ipv6_pd.prefix_len(),
                preferred_lifetime: 100,
                valid_lifetime: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply response for Rebind"),
    };

    assert!(matches!(resp.msg_type(), MessageType::Reply));

    // Verify IA_NA and IA_PD are returned with correct values
    let iana = resp.ia_na().expect("Response missing IA_NA");
    let iapd = resp.ia_pd().expect("Response missing IA_PD");

    assert_eq!(iana.t1, RENEWAL_TIME);
    assert_eq!(iana.t2, REBINDING_TIME);
    assert_eq!(iapd.t1, RENEWAL_TIME);
    assert_eq!(iapd.t2, REBINDING_TIME);

    // Verify addresses/prefixes
    let returned_na = resp.ia_na_address().unwrap();
    let returned_pd = resp.ia_pd_prefix().unwrap();
    assert_eq!(returned_na, reservation.ipv6_na);
    assert_eq!(returned_pd, reservation.ipv6_pd);
}

/// RFC 8415: Rebind with no reservation returns NoBinding in IA options
#[test]
fn rebind_no_reservation_returns_no_binding() {
    let (config, reservations, leases) = create_env();

    let mut msg = Message::new(MessageType::Rebind);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::ClientId(vec![0xde, 0xad, 0xbe, 0xef]));
    opts.insert(DhcpOption::IANA(IANA {
        id: 1,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAAddr(IAAddr {
                addr: "2001:db8::1234".parse().unwrap(),
                preferred_life: 100,
                valid_life: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply response"),
    };

    let returned_iana = resp.ia_na().expect("Reply missing IA_NA");

    // Verify NoBinding status is inside IA option
    let ia_status = returned_iana
        .opts
        .iter()
        .find_map(|opt| match opt {
            DhcpOption::StatusCode(code) => Some(code),
            _ => None,
        })
        .expect("IA_NA missing StatusCode");
    assert_eq!(ia_status.status, dhcproto::v6::Status::NoBinding);

    // Verify lifetimes are zeroed
    let returned_addr = returned_iana
        .opts
        .iter()
        .find_map(|opt| match opt {
            DhcpOption::IAAddr(addr) => Some(addr),
            _ => None,
        })
        .expect("IA_NA missing IAAddr");
    assert_eq!(returned_addr.preferred_life, 0);
    assert_eq!(returned_addr.valid_life, 0);
}

/// Verify that Renew response contains correct T1/T2 values per RFC 8415
#[test]
fn renew_response_has_correct_t1_t2() {
    let (config, reservations, leases) = create_env();

    let reservation = reservations
        .by_mac(RESERVATION_MAC)
        .expect("No reservation found");

    let mut msg = Message::new(MessageType::Renew);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::ClientId(vec![0xaa, 0xbb, 0xcc]));
    opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));
    opts.insert(DhcpOption::IANA(IANA {
        id: 1,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAAddr(IAAddr {
                addr: reservation.ipv6_na,
                preferred_life: 100,
                valid_life: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));
    opts.insert(DhcpOption::IAPD(IAPD {
        id: 2,
        t1: 0,
        t2: 0,
        opts: {
            let mut o = DhcpOptions::new();
            o.insert(DhcpOption::IAPrefix(IAPrefix {
                prefix_ip: reservation.ipv6_pd.addr(),
                prefix_len: reservation.ipv6_pd.prefix_len(),
                preferred_lifetime: 100,
                valid_lifetime: 200,
                opts: DhcpOptions::new(),
            }));
            o
        },
    }));

    let relay_msg = create_relay_forw(&msg);

    let resp = match crate::v6::handlers::handle_message(
        &config,
        &reservations,
        &leases,
        &msg,
        &relay_msg,
    ) {
        DhcpV6Response::Message(resp) => resp.message,
        _ => panic!("Expected Reply response"),
    };

    let iana = resp.ia_na().expect("Response missing IA_NA");
    let iapd = resp.ia_pd().expect("Response missing IA_PD");

    assert_eq!(iana.t1, RENEWAL_TIME, "IA_NA T1 should be RENEWAL_TIME");
    assert_eq!(iana.t2, REBINDING_TIME, "IA_NA T2 should be REBINDING_TIME");
    assert_eq!(iapd.t1, RENEWAL_TIME, "IA_PD T1 should be RENEWAL_TIME");
    assert_eq!(iapd.t2, REBINDING_TIME, "IA_PD T2 should be REBINDING_TIME");
}
