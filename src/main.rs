use dhcproto::{
    v6::{self, DhcpOption, DhcpOptions, IAAddr, Message, RelayMessage, StatusCode, IAPD},
    Decodable, Encodable,
};
use ipnet::Ipv6Net;
use std::{
    collections::HashMap,
    io,
    net::{Ipv6Addr, UdpSocket},
    time::{Duration, Instant},
};

// handle retransmissions
// metrics to clickhouse
// reservations from netbox
// renew of existing lease
// rapid commit option

// transaction id: used to match replies to requests

// 19.1.3.  Relay Agent Behavior with Prefix Delegation
//
//    A relay agent forwards messages containing prefix delegation options
//    in the same way as it would relay addresses (i.e., per
//    Sections 19.1.1 and 19.1.2).
//
//    If a server communicates with a client through a relay agent about
//    delegated prefixes, the server may need a protocol or other
//    out-of-band communication to configure routing information for
//    delegated prefixes on any router through which the client may forward
//    traffic.

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct ReservedAddress {
    na: Ipv6Addr,
    pd: Ipv6Net,
}

#[derive(Debug, Clone)]
#[allow(unused)]
enum LeaseSource {
    Duid,
    Mac,
}

#[derive(Debug, Clone)]
#[allow(unused)]
struct Lease {
    first_leased: Instant,
    last_leased: Instant,
    valid: Duration,
    source: LeaseSource,
    duid: Vec<u8>,
    mac: Option<String>,
}

#[allow(unused)]
struct Storage {
    duid_reservation: HashMap<Vec<u8>, ReservedAddress>,
    mac_reservation: HashMap<String, ReservedAddress>,
    current_leases: HashMap<ReservedAddress, Lease>,
}

impl Storage {
    fn leased_new(&mut self, leased_address: &ReservedAddress, lease_details: &Lease) {
        // TODO: check if this address was leased in the past and replace it?
        match self
            .current_leases
            .insert(leased_address.to_owned(), lease_details.to_owned())
        {
            Some(old_lease) => {
                println!("replaced existing lease {leased_address:?} {old_lease:?} with new lease {lease_details:?}")
            }
            None => println!(
                "First time leased address: {:?} to DUID {:?} MAC {:?}",
                leased_address, lease_details.duid, lease_details.mac
            ),
        }
    }
}

fn main() {
    let mut duid_reservation = HashMap::new();
    duid_reservation.insert(
        vec![
            29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
        ],
        ReservedAddress {
            na: Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
            pd: Ipv6Net::new(Ipv6Addr::new(1, 1, 1, 1, 0, 0, 0, 0), 48).unwrap(),
        },
    );

    let mut storage = Storage {
        duid_reservation,
        mac_reservation: HashMap::new(),
        current_leases: HashMap::new(),
    };

    let msg = dhcpv6_test_request();
    handle_message(&mut storage, msg);

    // only work with relayed messages
    // bind to address on host with port 567
    let socket = UdpSocket::bind("[::1]:567").expect("udp bind");
    let mut read_buf = [0u8; 1500];

    // listen for messages
    loop {
        // if the src is not listening on response, it may send a ICMP host unreachable
        // message which we need to handle
        let (amount, src) = match socket.recv_from(&mut read_buf) {
            Ok((amount, src)) => {
                println!("Received {amount} bytes from {src:?}");
                (amount, src)
            }
            Err(err) => {
                eprintln!("Error receiving: {err:?}");
                match err.kind() {
                    io::ErrorKind::NotFound => todo!(),
                    io::ErrorKind::PermissionDenied => todo!(),
                    io::ErrorKind::ConnectionRefused => todo!(),
                    io::ErrorKind::ConnectionReset => {
                        eprintln!("Sent response to host that responded with ICMP unreachable");
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

                if let Some(response_msg) = handle_message(&mut storage, inner_msg) {
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
                        Ok(sent) => println!("responded with {sent} bytes"),
                        Err(e) => eprintln!("Problem sending respones message: {e}"),
                    }
                }
            }
            Err(e) => {
                eprintln!("Unable to parse dhcp message {}", e);
            }
        };
    }
}

fn handle_message(storage: &mut Storage, msg: v6::Message) -> Option<v6::Message> {
    match msg.msg_type() {
        v6::MessageType::Solicit => {
            // check what kind of solicit: IA_NA, IA_PD, IA_NA & IA_PD
            // check if we have reservation for DUID, v6::DhcpOption::ClientId
            // check if we have reservation for MAC
            // respond with IA_NA option and or IA_PD option,

            println!("Received Solicit message");
            let client_id = client_id(&msg)?;
            println!("ClientID: {:?}", client_id);
            let reserved_address = storage.duid_reservation.get(&client_id).cloned();
            match reserved_address {
                Some(reservation) => {
                    let lease = Lease {
                        first_leased: Instant::now(),
                        last_leased: Instant::now(),
                        valid: Duration::from_secs(60 * 60 * 8),
                        source: LeaseSource::Duid,
                        duid: client_id,
                        mac: None,
                    };

                    storage.leased_new(&reservation, &lease);

                    // respond with a Reply message
                    let preferred_lifetime = 120;
                    let valid_lifetime = 240;

                    let mut reply = v6::Message::new_with_id(v6::MessageType::Reply, msg.xid());
                    let mut opts = v6::DhcpOptions::new();
                    opts.insert(DhcpOption::StatusCode(StatusCode {
                        status: v6::Status::Success,
                        msg: String::from(""),
                    }));

                    // Reply contains IA_NA address and IA_PD prefix as options.
                    // These options contain nested options with the actual addresses/prefixes
                    // ReplyOptions [IAPD[IAPrefix], IANA[IAAddr]]

                    // construct IA_PD information
                    let mut ia_pd_opts = DhcpOptions::new();
                    ia_pd_opts.insert(DhcpOption::IAPrefix(v6::IAPrefix {
                        preferred_lifetime,
                        valid_lifetime,
                        prefix_len: reservation.pd.prefix_len(),
                        prefix_ip: reservation.pd.addr(),
                        opts: DhcpOptions::new(),
                    }));
                    // add IA_PD information to Reply message
                    opts.insert(DhcpOption::IAPD(IAPD {
                        id: 1,
                        t1: preferred_lifetime,
                        t2: valid_lifetime,
                        opts: ia_pd_opts,
                    }));

                    // construct IA_NA information
                    let mut ia_na_opts = DhcpOptions::new();
                    ia_na_opts.insert(DhcpOption::IAAddr(IAAddr {
                        addr: reservation.na,
                        preferred_life: preferred_lifetime,
                        valid_life: valid_lifetime,
                        opts: DhcpOptions::new(),
                    }));
                    // add IA_NA information to Reply message
                    opts.insert(DhcpOption::IANA(v6::IANA {
                        id: 1,
                        t1: preferred_lifetime,
                        t2: valid_lifetime,
                        opts: ia_na_opts,
                    }));

                    reply.set_opts(opts);
                    Some(reply)
                }
                None => {
                    eprintln!("Solicit request with no reservation for DUID");
                    None
                }
            }
        }
        // v6::MessageType::Advertise => todo!(),
        // v6::MessageType::Request => todo!(),
        // v6::MessageType::Confirm => todo!(),

        // 18.2.4.  Creation and Transmission of Renew Messages
        //
        //   To extend the preferred and valid lifetimes for the leases assigned
        //   to the IAs and obtain new addresses or delegated prefixes for IAs,
        //   the client sends a Renew message to the server from which the leases
        //   were obtained; the Renew message includes IA options for the IAs
        //   whose lease lifetimes are to be extended.  The client includes IA
        //   Address options (see Section 21.6) within IA_NA (see Section 21.4)
        //   and IA_TA (see Section 21.5) options for the addresses assigned to
        //   the IAs.  The client includes IA Prefix options (see Section 21.22)
        //   within IA_PD options (see Section 21.21) for the delegated prefixes
        //   assigned to the IAs.
        v6::MessageType::Renew => {
            // client is refreshing existing lease, check that the addresses/prefixes sent
            // by the client are the ones we have reserved for them

            // TODO: client may ask for multiple IANA or IAPD
            // TODO: prefix size hinting 18.2.4
            let _client_iana = msg.opts().get(v6::OptionCode::IANA).and_then(|o| match o {
                DhcpOption::IANA(i) => Some(i),
                _ => None,
            });
            let _client_iapd = msg.opts().get(v6::OptionCode::IAPD).and_then(|o| match o {
                DhcpOption::IAPD(i) => Some(i),
                _ => None,
            });

            // TODO: message MUST include ServerIdentifier option AND match this Server's identity
            let _server_identifier =
                msg.opts()
                    .get(v6::OptionCode::ServerId)
                    .and_then(|o| match o {
                        DhcpOption::ServerId(i) => Some(i),
                        _ => None,
                    })?;

            // TODO: message MUST include a ClientIdentifier option
            let _client_identifier =
                msg.opts()
                    .get(v6::OptionCode::ClientId)
                    .and_then(|o| match o {
                        DhcpOption::ClientId(i) => Some(i),
                        _ => None,
                    })?;

            // if the lease cannot be renewed, set the preferred and valid lifetimes to 0
            // and optionally include new addresses/prefixes that the client can use
            let preferred_lifetime = 120;
            let valid_lifetime = 240;
            let prefix_len = 56;
            let prefix_ip = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
            let _new_addr: Option<ReservedAddress> = None;

            // respond with a Reply message
            let mut reply = v6::Message::new_with_id(v6::MessageType::Reply, msg.xid());
            let mut opts = v6::DhcpOptions::new();
            opts.insert(DhcpOption::StatusCode(StatusCode {
                status: v6::Status::Success,
                msg: String::from(""),
            }));
            opts.insert(DhcpOption::IAPrefix(v6::IAPrefix {
                preferred_lifetime,
                valid_lifetime,
                prefix_len,
                prefix_ip,
                opts: DhcpOptions::new(),
            }));

            reply.set_opts(opts);
            Some(reply)
        }
        // v6::MessageType::Rebind => todo!(),
        // v6::MessageType::Reply => todo!(),
        // v6::MessageType::Release => todo!(),
        // v6::MessageType::Decline => todo!(),
        // v6::MessageType::Reconfigure => todo!(),
        // v6::MessageType::InformationRequest => todo!(),
        // v6::MessageType::RelayForw => todo!(),
        // v6::MessageType::RelayRepl => todo!(),
        // v6::MessageType::LeaseQuery => todo!(),
        // v6::MessageType::LeaseQueryReply => todo!(),
        // v6::MessageType::LeaseQueryDone => todo!(),
        // v6::MessageType::LeaseQueryData => todo!(),
        // v6::MessageType::ReconfigureRequest => todo!(),
        // v6::MessageType::ReconfigureReply => todo!(),
        // v6::MessageType::DHCPv4Query => todo!(),
        // v6::MessageType::DHCPv4Response => todo!(),
        // v6::MessageType::Unknown(_) => todo!(),
        _ => {
            eprintln!(
                "MessageType {:?} not implemented by ddhcpv6",
                msg.msg_type()
            );
            None
        }
    }
}

fn client_id(msg: &Message) -> Option<Vec<u8>> {
    msg.opts().iter().find_map(|opt| match opt {
        v6::DhcpOption::ClientId(id) => Some(id.to_owned()),
        _ => None,
    })
}

#[allow(unused)]
fn dhcpv6_test_request() -> v6::Message {
    let duid = vec![
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    ];
    // construct a new Message with a random xid
    let mut msg = v6::Message::new(v6::MessageType::Solicit);
    // set an option
    msg.opts_mut().insert(v6::DhcpOption::ClientId(duid));

    msg
}

#[cfg(test)]
mod tests {
    use v6::MessageType;

    use super::*;

    #[test]
    fn reply_test() {
        let mut opts = v6::DhcpOptions::new();
        opts.insert(DhcpOption::RelayMsg(v6::RelayMessageData::Message(
            v6::Message::new(v6::MessageType::Solicit),
        )));

        let reply = v6::RelayMessage {
            msg_type: v6::MessageType::RelayForw,
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
            0x01, 0xa4, 0xcf, 0x70, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55,
            0x31, 0x8f, 0x19, 0x94, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
            0x07, 0x08, 0x00, 0x00, 0x0b, 0x40, 0x00, 0x06, 0x00, 0x02, 0x00, 0x17, 0x00, 0x08,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0c, 0x00, 0x00,
            0x00, 0x05, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x0b, 0x40,
        ];

        let msg = v6::Message::from_bytes(&packet_bytes).unwrap();
        assert!(matches!(msg.msg_type(), MessageType::Solicit));
        assert_eq!(msg.xid(), [164, 207, 112]);
    }

    #[test]
    fn kea_advertise() {
        let packet_bytes: [u8; 125] = [
            0x02, 0xa4, 0xcf, 0x70, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55,
            0x31, 0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x2d, 0xf2,
            0x39, 0xc7, 0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03, 0x00, 0x28, 0x00, 0x00,
            0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x05, 0x00, 0x18,
            0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x19, 0x00, 0x29,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x1a,
            0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x38, 0x26, 0x05, 0xcb,
            0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let msg = v6::Message::from_bytes(&packet_bytes).unwrap();
        assert!(matches!(msg.msg_type(), MessageType::Advertise));
        assert_eq!(msg.xid(), [164, 207, 112]);
    }

    #[test]
    fn mikrotik_request() {
        let packet_bytes: [u8; 137] = [
            0x03, 0x2a, 0xcb, 0x85, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55,
            0x31, 0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x2d, 0xf2,
            0x39, 0xc7, 0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03, 0x00, 0x28, 0x00, 0x00,
            0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x05, 0x00, 0x18,
            0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x06, 0x00, 0x02,
            0x00, 0x17, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x19, 0x00, 0x29, 0x00, 0x00,
            0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x1a, 0x00, 0x19,
            0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x38, 0x26, 0x05, 0xcb, 0x40, 0x80,
            0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let msg = v6::Message::from_bytes(&packet_bytes).unwrap();
        assert!(matches!(msg.msg_type(), MessageType::Request));
        assert_eq!(msg.xid(), [42, 203, 133]);
    }

    #[test]
    fn kea_reply() {
        let packet_bytes: [u8; 125] = [
            0x07, 0x2a, 0xcb, 0x85, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x08, 0x55,
            0x31, 0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x2d, 0xf2,
            0x39, 0xc7, 0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03, 0x00, 0x28, 0x00, 0x00,
            0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x05, 0x00, 0x18,
            0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x19, 0x00, 0x29,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x1a,
            0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x38, 0x26, 0x05, 0xcb,
            0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let msg = v6::Message::from_bytes(&packet_bytes).unwrap();
        assert!(matches!(msg.msg_type(), MessageType::Reply));
        assert_eq!(msg.xid(), [42, 203, 133]);
    }
}
