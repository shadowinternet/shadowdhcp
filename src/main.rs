use dhcproto::{
    v6::{self, DhcpOption, DhcpOptions, StatusCode},
    Decodable, Encodable,
};
use ipnet::Ipv6Net;
use std::{
    collections::HashMap,
    net::{Ipv6Addr, UdpSocket},
    time::{Duration, Instant},
};

// handle relaying
// handle retransmissions
// metrics to clickhouse
// reservations from netbox
// renew of existing lease
// rapid commit option
// relays may send Interface-ID option which must be echo'd back in replies

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
        let (amount, _src) = socket.recv_from(&mut read_buf).expect("udp receive");
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
                    // opts.insert(v6::DhcpOption::RelayMsg(v6::RelayMessage::))
                    let write_buf = response_msg.to_vec().expect("encoding response msg");
                    match socket.send(&write_buf) {
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
            let opts = msg.opts();
            for opt in opts.iter() {
                match opt {
                    v6::DhcpOption::ClientId(id) => {
                        println!("option ClientID: {:?}", id);
                        let reserved_address = storage.duid_reservation.get(id).cloned();
                        match reserved_address {
                            Some(reservation) => {
                                let lease = Lease {
                                    first_leased: Instant::now(),
                                    last_leased: Instant::now(),
                                    valid: Duration::from_secs(60 * 60 * 8),
                                    source: LeaseSource::Duid,
                                    duid: id.to_owned(),
                                    mac: None,
                                };

                                storage.leased_new(&reservation, &lease);
                            }
                            None => eprintln!("Solicit request with no reservation for DUID"),
                        }
                    }
                    // v6::DhcpOption::ServerId(_) => todo!(),
                    // v6::DhcpOption::IANA(_) => todo!(),
                    // v6::DhcpOption::IATA(_) => todo!(),
                    // v6::DhcpOption::IAAddr(_) => todo!(),
                    // v6::DhcpOption::ORO(_) => todo!(),
                    // v6::DhcpOption::Preference(_) => todo!(),
                    // v6::DhcpOption::ElapsedTime(_) => todo!(),
                    // v6::DhcpOption::RelayMsg(_) => todo!(),
                    // v6::DhcpOption::Authentication(_) => todo!(),
                    // v6::DhcpOption::ServerUnicast(_) => todo!(),
                    // v6::DhcpOption::StatusCode(_) => todo!(),
                    // v6::DhcpOption::RapidCommit => todo!(),
                    // v6::DhcpOption::UserClass(_) => todo!(),
                    // v6::DhcpOption::VendorClass(_) => todo!(),
                    // v6::DhcpOption::VendorOpts(_) => todo!(),
                    // v6::DhcpOption::InterfaceId(_) => todo!(),
                    // v6::DhcpOption::ReconfMsg(_) => todo!(),
                    // v6::DhcpOption::ReconfAccept => todo!(),
                    // v6::DhcpOption::DomainNameServers(_) => todo!(),
                    // v6::DhcpOption::DomainSearchList(_) => todo!(),
                    // v6::DhcpOption::IAPD(_) => todo!(),
                    // v6::DhcpOption::IAPrefix(_) => todo!(),
                    // v6::DhcpOption::InformationRefreshTime(_) => todo!(),
                    // v6::DhcpOption::Unknown(_) => todo!(),
                    _ => {
                        eprintln!("Unrecognized option: {:?}", opt);
                    }
                }
            }
            None
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
            let _server_identifier =
                msg.opts()
                    .get(v6::OptionCode::ServerId)
                    .and_then(|o| match o {
                        DhcpOption::ServerId(i) => Some(i),
                        _ => None,
                    })?;
            let _client_identifier =
                msg.opts()
                    .get(v6::OptionCode::ClientId)
                    .and_then(|o| match o {
                        DhcpOption::ClientId(i) => Some(i),
                        _ => None,
                    })?;

            // TODO: message MUST include ServerIdentifier option AND match this Server's identity
            // TODO: message MUST include a ClientIdentifier option

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
}
