use advmac::MacAddr6;
use arc_swap::ArcSwapAny;
use dhcproto::{
    v6::{self, DhcpOption, DhcpOptions, IAAddr, IAPrefix, Message, RelayMessage, IANA, IAPD},
    Decodable, Encodable,
};
use ipnet::Ipv6Net;
use shadow_dhcpv6::{config::Config, leasedb::LeaseDb, reservationdb::ReservationDb, LeaseV6};
use std::{
    io,
    net::{Ipv6Addr, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, error, field, info, instrument, trace, Span};

// handle retransmissions
// renew of existing lease

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

const PREFERRED_LIFETIME: u32 = 120;
const VALID_LIFETIME: u32 = 240;

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
                trace!("Data: {:x?}", &read_buf[..amount]);
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

                if let Some(response_msg) = handle_message(
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

#[instrument(skip(config, reservations, leases, msg, relay_msg),
fields(client_id = field::Empty, xid = ?msg.xid()))]
fn handle_solicit(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    msg: v6::Message,
    relay_msg: &v6::RelayMessage,
) -> Option<v6::Message> {
    // Servers MUST discard any Solicit messages that do not include a Client identifier
    // option or that do include a Server Identifier option
    let client_id = shadow_dhcpv6::Duid::from(msg.client_id()?.to_vec());
    Span::current().record("client_id", field::display(&client_id.to_colon_string()));
    relay_msg.hw_addr().inspect(|hw| info!("hw_addr: {:?}", hw));

    if msg.server_id().is_some() {
        info!("Client included a server_id field, ignoring");
        return None;
    }

    // Rapid Commit option - The client may request the expedited two-message exchange
    // by adding the Rapid Commit option to the first Solicit request
    let msg_type = if msg.rapid_commit() {
        // TODO: the server needs to include the rapid commit option in replys to a rapid commit
        // https://datatracker.ietf.org/doc/html/rfc8415#section-21.14
        debug!("Solicit 2 message exchange, rapid commit");
        v6::MessageType::Reply
    } else {
        debug!("Solicit 4 message exchange");
        v6::MessageType::Advertise
    };

    let reserved_address = reservations.by_duid(&client_id).or(relay_msg
        .hw_addr()
        .and_then(|mac| leases.get_opt82_by_mac(&mac))
        .and_then(|opt82| reservations.by_opt82(&opt82)));
    match reserved_address {
        Some(reservation) => {
            let lease = LeaseV6 {
                first_leased: Instant::now(),
                last_leased: Instant::now(),
                valid: Duration::from_secs(u64::from(VALID_LIFETIME)),
                duid: client_id.clone(),
                mac: None,
            };

            leases.leased_new_v6(&reservation, lease);

            let mut reply = v6::Message::new_with_id(msg_type, msg.xid());
            let opts = reply.opts_mut();

            // Reply contains IA_NA address and IA_PD prefix as options.
            // These options contain nested options with the actual addresses/prefixes
            // ReplyOptions [IAPD[IAPrefix], IANA[IAAddr]]

            // construct IA_PD information
            if msg.ia_pd().is_some() {
                let mut ia_pd_opts = DhcpOptions::new();
                ia_pd_opts.insert(DhcpOption::IAPrefix(v6::IAPrefix {
                    preferred_lifetime: PREFERRED_LIFETIME,
                    valid_lifetime: VALID_LIFETIME,
                    prefix_len: reservation.ipv6_pd.prefix_len(),
                    prefix_ip: reservation.ipv6_pd.addr(),
                    opts: DhcpOptions::new(),
                }));
                // add IA_PD information to Reply message
                opts.insert(DhcpOption::IAPD(IAPD {
                    id: 1,
                    t1: PREFERRED_LIFETIME,
                    t2: VALID_LIFETIME,
                    opts: ia_pd_opts,
                }));
            }

            // construct IA_NA information
            if msg.ia_na().is_some() {
                let mut ia_na_opts = DhcpOptions::new();
                ia_na_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: reservation.ipv6_na,
                    preferred_life: PREFERRED_LIFETIME,
                    valid_life: VALID_LIFETIME,
                    opts: DhcpOptions::new(),
                }));
                // add IA_NA information to Reply message
                opts.insert(DhcpOption::IANA(v6::IANA {
                    id: 1,
                    t1: PREFERRED_LIFETIME,
                    t2: VALID_LIFETIME,
                    opts: ia_na_opts,
                }));
            }

            opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));
            opts.insert(DhcpOption::ClientId(client_id.bytes));
            Some(reply)
        }
        None => {
            info!("Solicit request with no reservation for DUID");
            None
        }
    }
}

#[instrument(skip(config, reservations, leases, msg, relay_msg),
fields(client_id = field::Empty, xid = ?msg.xid()))]
fn handle_renew(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    msg: v6::Message,
    relay_msg: &v6::RelayMessage,
) -> Option<Message> {
    // client is refreshing existing lease, check that the addresses/prefixes sent
    // by the client are the ones we have reserved for them

    // message MUST include a ClientIdentifier option
    let client_id = shadow_dhcpv6::Duid::from(msg.client_id()?.to_vec());
    Span::current().record("client_id", field::display(&client_id.to_colon_string()));
    relay_msg.hw_addr().inspect(|hw| info!("hw_addr: {:?}", hw));

    // message MUST include ServerIdentifier option AND match this Server's identity
    if msg.server_id()? != config.v6_server_id.bytes {
        error!("Client sent server_identifier that doesn't match this server");
        return None;
    }

    let mut reply = v6::Message::new_with_id(v6::MessageType::Reply, msg.xid());
    let opts = reply.opts_mut();

    let reserved_address = reservations.by_duid(&client_id).or(relay_msg
        .hw_addr()
        .and_then(|mac| leases.get_opt82_by_mac(&mac))
        .and_then(|opt82| reservations.by_opt82(&opt82)));
    match reserved_address {
        Some(reservation) => {
            // check if our server reservation matches what the client sent
            if msg.opts().iter().any(|o| match o {
                DhcpOption::IANA(iana) => iana.opts.iter().any(|io| match io {
                    DhcpOption::IAAddr(addr) => reservation.ipv6_na == addr.addr,
                    _ => false,
                }),
                _ => false,
            }) {
                let mut ia_na_opts = DhcpOptions::new();
                ia_na_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: reservation.ipv6_na,
                    preferred_life: PREFERRED_LIFETIME,
                    valid_life: VALID_LIFETIME,
                    opts: DhcpOptions::new(),
                }));
                // add IA_NA information to Reply message
                opts.insert(DhcpOption::IANA(v6::IANA {
                    id: 1, // TODO: match id of incoming msg
                    t1: PREFERRED_LIFETIME,
                    t2: VALID_LIFETIME,
                    opts: ia_na_opts,
                }));
            }

            if msg.opts().iter().any(|o| match o {
                DhcpOption::IAPD(iapd) => iapd.opts.iter().any(|io| match io {
                    DhcpOption::IAPrefix(prefix) => {
                        reservation.ipv6_pd.addr() == prefix.prefix_ip
                            && reservation.ipv6_pd.prefix_len() == prefix.prefix_len
                    }
                    _ => false,
                }),
                _ => false,
            }) {
                let mut ia_pd_opts = DhcpOptions::new();
                ia_pd_opts.insert(DhcpOption::IAPrefix(v6::IAPrefix {
                    preferred_lifetime: PREFERRED_LIFETIME,
                    valid_lifetime: VALID_LIFETIME,
                    prefix_len: reservation.ipv6_pd.prefix_len(),
                    prefix_ip: reservation.ipv6_pd.addr(),
                    opts: DhcpOptions::new(),
                }));
                // add IA_PD information to Reply message
                opts.insert(DhcpOption::IAPD(IAPD {
                    id: 1,
                    t1: PREFERRED_LIFETIME,
                    t2: VALID_LIFETIME,
                    opts: ia_pd_opts,
                }));
            }

            // TODO: redo this
            if opts.iter().count() > 0 {
                let lease = LeaseV6 {
                    first_leased: Instant::now(),
                    last_leased: Instant::now(),
                    valid: Duration::from_secs(u64::from(VALID_LIFETIME)),

                    duid: client_id.clone(),
                    mac: None,
                };
                leases.leased_new_v6(&reservation, lease);
            }
        }
        None => {
            // if the lease cannot be renewed, set the preferred and valid lifetimes to 0
            // TODO: optionally include new addresses/prefixes that the client can use

            for opt in msg.opts().iter() {
                match opt {
                    DhcpOption::IANA(iana) => {
                        let mut iana_new = iana.clone();
                        let addr: Option<&mut IAAddr> =
                            iana_new.opts.iter_mut().find_map(|o| match o {
                                DhcpOption::IAAddr(addr) => Some(addr),
                                _ => None,
                            });
                        if let Some(a) = addr {
                            a.valid_life = 0;
                            a.preferred_life = 0;
                        }

                        opts.insert(DhcpOption::IANA(iana_new));
                    }
                    DhcpOption::IAPD(iapd) => {
                        let mut iapd_new = iapd.clone();
                        let prefix: Option<&mut IAPrefix> =
                            iapd_new.opts.iter_mut().find_map(|o| match o {
                                DhcpOption::IAPrefix(prefix) => Some(prefix),
                                _ => None,
                            });
                        if let Some(p) = prefix {
                            p.valid_lifetime = 0;
                            p.preferred_lifetime = 0;
                        }

                        opts.insert(DhcpOption::IAPD(iapd_new));
                    }
                    _ => (),
                }
            }
        }
    };

    opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));
    opts.insert(DhcpOption::ClientId(client_id.bytes));
    Some(reply)
}

#[instrument(skip(config, reservations, leases, msg, relay_msg),
fields(client_id = field::Empty, xid = ?msg.xid()))]
fn handle_request(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    msg: v6::Message,
    relay_msg: &v6::RelayMessage,
) -> Option<Message> {
    // Servers MUST discard any Request messages that:
    // * does not include a Client Identifier
    // * does not include a Server Identifier option
    // * includes a Server Identifier option that does not match this server's DUID
    let client_id = shadow_dhcpv6::Duid::from(msg.client_id()?.to_vec());
    Span::current().record("client_id", field::display(&client_id.to_colon_string()));
    relay_msg.hw_addr().inspect(|hw| info!("hw_addr: {:?}", hw));

    if msg.server_id()? != config.v6_server_id.bytes {
        error!("Client sent server_identifier that doesn't match this server");
        return None;
    }

    let reserved_address = reservations.by_duid(&client_id).or(relay_msg
        .hw_addr()
        .and_then(|mac| leases.get_opt82_by_mac(&mac))
        .and_then(|opt82| reservations.by_opt82(&opt82)));
    match reserved_address {
        Some(reservation) => {
            let lease = LeaseV6 {
                first_leased: Instant::now(),
                last_leased: Instant::now(),
                valid: Duration::from_secs(u64::from(VALID_LIFETIME)),
                duid: client_id.clone(),
                mac: None,
            };

            leases.leased_new_v6(&reservation, lease);

            let mut reply = v6::Message::new_with_id(v6::MessageType::Reply, msg.xid());
            let opts = reply.opts_mut();

            // Reply contains IA_NA address and IA_PD prefix as options.
            // These options contain nested options with the actual addresses/prefixes
            // ReplyOptions [IAPD[IAPrefix], IANA[IAAddr]]

            // construct IA_PD information
            if msg.ia_pd().is_some() {
                let mut ia_pd_opts = DhcpOptions::new();
                ia_pd_opts.insert(DhcpOption::IAPrefix(v6::IAPrefix {
                    preferred_lifetime: PREFERRED_LIFETIME,
                    valid_lifetime: VALID_LIFETIME,
                    prefix_len: reservation.ipv6_pd.prefix_len(),
                    prefix_ip: reservation.ipv6_pd.addr(),
                    opts: DhcpOptions::new(),
                }));
                // add IA_PD information to Reply message
                opts.insert(DhcpOption::IAPD(IAPD {
                    id: 1,
                    t1: PREFERRED_LIFETIME,
                    t2: VALID_LIFETIME,
                    opts: ia_pd_opts,
                }));
            }

            // construct IA_NA information
            if msg.ia_na().is_some() {
                let mut ia_na_opts = DhcpOptions::new();
                ia_na_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: reservation.ipv6_na,
                    preferred_life: PREFERRED_LIFETIME,
                    valid_life: VALID_LIFETIME,
                    opts: DhcpOptions::new(),
                }));
                // add IA_NA information to Reply message
                opts.insert(DhcpOption::IANA(v6::IANA {
                    id: 1,
                    t1: PREFERRED_LIFETIME,
                    t2: VALID_LIFETIME,
                    opts: ia_na_opts,
                }));
            }

            opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));
            opts.insert(DhcpOption::ClientId(client_id.bytes));
            Some(reply)
        }
        None => {
            info!("No reservation found");
            None
        }
    }
}

fn handle_message(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    msg: v6::Message,
    relay_msg: &v6::RelayMessage,
) -> Option<v6::Message> {
    match msg.msg_type() {
        // A client sends a Solicit message to locate servers.
        // https://datatracker.ietf.org/doc/html/rfc8415#section-16.2
        // Four-message exchange - Solicit -> Advertisement -> Request -> Reply
        // Two-message exchange (rapid commit) - Solicit -> Reply
        v6::MessageType::Solicit => handle_solicit(config, reservations, leases, msg, relay_msg),
        // Servers always discard Advertise
        v6::MessageType::Advertise => None,
        // A client sends a Request as part of the 4 message exchange to receive an initial address/prefix
        // https://datatracker.ietf.org/doc/html/rfc8415#section-16.4
        v6::MessageType::Request => handle_request(config, reservations, leases, msg, relay_msg),
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
        v6::MessageType::Renew => handle_renew(config, reservations, leases, msg, relay_msg),
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
            error!(
                "MessageType `{:?}` not implemented by ddhcpv6",
                msg.msg_type()
            );
            None
        }
    }
}

trait ShadowMessageExtV6 {
    fn client_id(&self) -> Option<&[u8]>;
    fn server_id(&self) -> Option<&[u8]>;
    fn rapid_commit(&self) -> bool;
    fn ia_na(&self) -> Option<&IANA>;
    fn ia_pd(&self) -> Option<&IAPD>;
    #[allow(unused)]
    fn ia_na_address(&self) -> Option<Ipv6Addr>;
    #[allow(unused)]
    fn ia_pd_prefix(&self) -> Option<Ipv6Net>;
}

trait HardwareAddressFromMessage {
    fn hw_addr(&self) -> Option<MacAddr6>;
}

impl ShadowMessageExtV6 for Message {
    fn client_id(&self) -> Option<&[u8]> {
        self.opts().iter().find_map(|opt| match opt {
            v6::DhcpOption::ClientId(id) => Some(id.as_slice()),
            _ => None,
        })
    }

    fn server_id(&self) -> Option<&[u8]> {
        self.opts().iter().find_map(|opt| match opt {
            v6::DhcpOption::ServerId(id) => Some(id.as_slice()),
            _ => None,
        })
    }

    fn rapid_commit(&self) -> bool {
        self.opts()
            .iter()
            .any(|opt| matches!(opt, v6::DhcpOption::RapidCommit))
    }

    fn ia_na(&self) -> Option<&IANA> {
        self.opts().iter().find_map(|opt| match opt {
            v6::DhcpOption::IANA(iana) => Some(iana),
            _ => None,
        })
    }

    fn ia_na_address(&self) -> Option<Ipv6Addr> {
        self.ia_na().and_then(|na| {
            na.opts.iter().find_map(|opt| match opt {
                v6::DhcpOption::IAAddr(ia) => Some(ia.addr),
                _ => None,
            })
        })
    }

    fn ia_pd(&self) -> Option<&IAPD> {
        self.opts().iter().find_map(|opt| match opt {
            v6::DhcpOption::IAPD(iapd) => Some(iapd),
            _ => None,
        })
    }

    fn ia_pd_prefix(&self) -> Option<Ipv6Net> {
        self.ia_pd().and_then(|pd| {
            pd.opts.iter().find_map(|opt| match opt {
                v6::DhcpOption::IAPrefix(ia) => Ipv6Net::new(ia.prefix_ip, ia.prefix_len).ok(),
                _ => None,
            })
        })
    }
}

impl HardwareAddressFromMessage for RelayMessage {
    /// Try to extract a link layer address from the client message by using the
    /// DHCPv6 Client Link-Layer Address option, RFC6939
    /// <https://datatracker.ietf.org/doc/html/rfc6939#section-4>
    /// TODO: add fallbacks for other methods to get the link layer address
    /// TODO: return multiple possible link layer addresses
    fn hw_addr(&self) -> Option<MacAddr6> {
        self.opts().iter().find_map(|opt| match opt {
            v6::DhcpOption::ClientLinklayerAddress(ll) if ll.address.len() == 16 => {
                let mut bytes: [u8; 16] = [0; 16];
                bytes.copy_from_slice(&ll.address[0..16]);
                let link_local_addr = Ipv6Addr::from(bytes);
                MacAddr6::try_from_link_local_ipv6(link_local_addr).ok()
            }
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Reservation;
    use shadow_dhcpv6::Option82;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use v6::MessageType;

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
        assert!(msg.ia_na().is_some());
        assert!(msg.ia_pd().is_some());
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
        assert!(msg.ia_na().is_some());
        assert!(msg.ia_pd().is_some());
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

    #[test]
    fn mikrotik_relay_forw_solicit_to_server() {
        let packet_bytes: [u8; 124] = [
            0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x55,
            0x31, 0xff, 0xfe, 0x8f, 0x19, 0x98, 0x00, 0x4f, 0x00, 0x08, 0x00, 0x01, 0x0a, 0x55,
            0x31, 0x8f, 0x19, 0x98, 0x00, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x09,
            0x00, 0x42, 0x01, 0x9c, 0x31, 0xb2, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01,
            0x08, 0x55, 0x31, 0x8f, 0x19, 0x94, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x0b, 0x40, 0x00, 0x06, 0x00, 0x02, 0x00, 0x17,
            0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0c,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x0b, 0x40,
        ];

        let msg = v6::RelayMessage::from_bytes(&packet_bytes).unwrap();
        assert!(matches!(msg.msg_type, MessageType::RelayForw));
        println!("{msg:?}");
    }

    #[test]
    fn mikrotik_relay_reply_server_advertise_to_client() {
        let packet_bytes: [u8; 171] = [
            0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x55,
            0x31, 0xff, 0xfe, 0x8f, 0x19, 0x98, 0x00, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c,
            0x00, 0x09, 0x00, 0x7d, 0x02, 0x9c, 0x31, 0xb2, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
            0x00, 0x01, 0x08, 0x55, 0x31, 0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01,
            0x00, 0x01, 0x2d, 0xf2, 0x39, 0xc7, 0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03,
            0x00, 0x28, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0,
            0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0,
            0x00, 0x19, 0x00, 0x29, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00,
            0x07, 0xd0, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0,
            0x38, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];

        let msg = v6::RelayMessage::from_bytes(&packet_bytes).unwrap();
        assert!(matches!(msg.msg_type, MessageType::RelayRepl));
        println!("{msg:?}");
    }

    #[test]
    fn mikrotik_relay_forw_request_to_server() {
        let packet_bytes: [u8; 195] = [
            0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x55,
            0x31, 0xff, 0xfe, 0x8f, 0x19, 0x98, 0x00, 0x4f, 0x00, 0x08, 0x00, 0x01, 0x0a, 0x55,
            0x31, 0x8f, 0x19, 0x98, 0x00, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x09,
            0x00, 0x89, 0x03, 0xcb, 0x9e, 0x48, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01,
            0x08, 0x55, 0x31, 0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
            0x2d, 0xf2, 0x39, 0xc7, 0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03, 0x00, 0x28,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x05,
            0x00, 0x18, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x06,
            0x00, 0x02, 0x00, 0x17, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x19, 0x00, 0x29,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x1a,
            0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0, 0x38, 0x26, 0x05, 0xcb,
            0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let msg = v6::RelayMessage::from_bytes(&packet_bytes).unwrap();
        assert!(matches!(msg.msg_type, MessageType::RelayForw));

        let link_layer_addr = msg
            .opts()
            .iter()
            .find_map(|opt| match opt {
                v6::DhcpOption::ClientLinklayerAddress(ll) => Some(ll),
                _ => None,
            })
            .unwrap();
        println!("{link_layer_addr:?}");
        println!("{msg:?}");
    }

    #[test]
    fn mikrotik_relay_reply_server_reply_to_client() {
        let packet_bytes: [u8; 171] = [
            0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x55,
            0x31, 0xff, 0xfe, 0x8f, 0x19, 0x98, 0x00, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c,
            0x00, 0x09, 0x00, 0x7d, 0x07, 0xcb, 0x9e, 0x48, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
            0x00, 0x01, 0x08, 0x55, 0x31, 0x8f, 0x19, 0x94, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01,
            0x00, 0x01, 0x2d, 0xf2, 0x39, 0xc7, 0xbc, 0x24, 0x11, 0xa7, 0x20, 0x34, 0x00, 0x03,
            0x00, 0x28, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0,
            0x00, 0x05, 0x00, 0x18, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0,
            0x00, 0x19, 0x00, 0x29, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00,
            0x07, 0xd0, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x0f, 0xa0,
            0x38, 0x26, 0x05, 0xcb, 0x40, 0x80, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];
        let msg = v6::RelayMessage::from_bytes(&packet_bytes).unwrap();
        assert!(matches!(msg.msg_type, MessageType::RelayRepl));
        println!("{msg:?}");
    }

    fn basic_config() -> Config {
        let subnets_v4 = vec![
            V4Subnet {
                net: "192.168.0.0/24".parse().unwrap(),
                gateway: "192.168.0.1".parse().unwrap(),
            },
            V4Subnet {
                net: "100.110.1.0/24".parse().unwrap(),
                gateway: "100.110.1.1".parse().unwrap(),
            },
        ];
        let dns_v4 = vec![Ipv4Addr::from([8, 8, 8, 8]), Ipv4Addr::from([8, 8, 4, 4])];
        let v4_server_id = Ipv4Addr::from([23, 159, 144, 10]);
        let v6_server_id = Duid::from(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let config = Config {
            v4_server_id,
            dns_v4,
            subnets_v4,
            v6_server_id,
            option82_extractors: extractors::get_all_extractors().into_values().collect(),
        };
    }

    #[test]
    fn dynamic_opt82_binding() {
        let json_str = r#"
        [
            {
                "ipv4": "192.168.1.111",
                "ipv6_na": "2605:cb40:1:6::1",
                "ipv6_pd": "2605:cb40:1:7::/56",
                "option82": {"circuit": "99-11-22-33-44-55", "remote": "eth2:100"}
            },
            {
                "ipv4": "192.168.1.112",
                "ipv6_na": "2605:cb40:1:8::1",
                "ipv6_pd": "2605:cb40:1:9::/56",
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
        let link_local_addr = mac.to_link_local_ipv6();

        let duid = vec![0x00, 0x01];
        let mut msg = Message::new(v6::MessageType::Solicit);
        let msg_opts = msg.opts_mut();
        msg_opts.insert(v6::DhcpOption::ClientId(duid));
        msg_opts.insert(v6::DhcpOption::IANA(IANA {
            id: 1,
            t1: 100,
            t2: 1000,
            opts: DhcpOptions::new(),
        }));
        msg_opts.insert(v6::DhcpOption::IAPD(IAPD {
            id: 1,
            t1: 100,
            t2: 1000,
            opts: DhcpOptions::new(),
        }));

        // pack msg into a relay_msg
        let mut relay_opts = v6::DhcpOptions::new();
        relay_opts.insert(v6::DhcpOption::RelayMsg(v6::RelayMessageData::Message(
            msg.clone(),
        )));
        relay_opts.insert(v6::DhcpOption::ClientLinklayerAddress(
            v6::ClientLinklayerAddress {
                address_type: 1,
                address: link_local_addr.octets().to_vec(),
            },
        ));

        let relay_msg = RelayMessage {
            msg_type: v6::MessageType::RelayForw,
            hop_count: 0,
            link_addr: Ipv6Addr::new(8, 8, 8, 8, 8, 8, 8, 8),
            peer_addr: Ipv6Addr::new(9, 9, 9, 9, 9, 9, 9, 9),
            opts: relay_opts,
        };

        let resp = handle_solicit(&basic_config(), &db, &leases, msg, &relay_msg).unwrap();
        assert!(matches!(resp.msg_type(), v6::MessageType::Advertise));

        let reservation = db.by_opt82(&opt82).unwrap();
        assert_eq!(resp.ia_na_address().unwrap(), reservation.ipv6_na);
        assert_eq!(resp.ia_pd_prefix().unwrap(), reservation.ipv6_pd);
    }
}
