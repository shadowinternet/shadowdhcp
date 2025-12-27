use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dhcproto::v6::{
    DhcpOption, DhcpOptions, IAAddr, IAPrefix, Message, MessageType, RelayMessage, IANA, IAPD,
};
use shadow_dhcpv6::{LeaseV6, Reservation};

use crate::analytics::events::ReservationMatch;
use crate::config::Config;
use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;
use tracing::{debug, error, field, info, instrument, Span};

use crate::v6::{
    extensions::{ShadowMessageExtV6, ShadowRelayMessageExtV6},
    reservation::find_reservation,
    PREFERRED_LIFETIME, REBINDING_TIME, RENEWAL_TIME, VALID_LIFETIME,
};

/// A DHCPv6 response message produced by the server.
///
/// If a reservation was used to construct the message, it is included for logging
/// and observability.
pub struct ResponseMessage {
    pub message: Message,
    pub reservation: Option<Arc<Reservation>>,
    pub reservation_match: Option<ReservationMatch>,
}

#[derive(Debug, Copy, Clone)]
pub enum NoResponseReason {
    NoClientId,
    UnexpectedServerId,
    WrongServerId,
    NoServerId,
    NoReservation,
    Discarded,
}

impl NoResponseReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            NoResponseReason::NoClientId => "NoClientId",
            NoResponseReason::UnexpectedServerId => "UnexpectedServerId",
            NoResponseReason::WrongServerId => "WrongServerId",
            NoResponseReason::NoServerId => "NoServerId",
            NoResponseReason::NoReservation => "NoReservation",
            NoResponseReason::Discarded => "Discarded",
        }
    }
}

/// Result of processing an incoming DHCPv6 message.
///
/// `DhcpV6Response` indicates whether the server should send a DHCPv6
/// message back to the client or intentionally remain silent.
pub enum DhcpV6Response {
    Message(ResponseMessage),
    NoResponse(NoResponseReason),
}

#[instrument(skip(config, reservations, leases, msg, relay_msg),
fields(client_id = field::Empty, xid = ?msg.xid()))]
fn handle_solicit(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    msg: &Message,
    relay_msg: &RelayMessage,
) -> DhcpV6Response {
    // Servers MUST discard any Solicit messages that do not include a Client identifier
    // option or that do include a Server Identifier option
    let client_id = match msg.client_id() {
        Some(bytes) => shadow_dhcpv6::Duid::from(bytes.to_vec()),
        None => return DhcpV6Response::NoResponse(NoResponseReason::NoClientId),
    };

    Span::current().record("client_id", field::display(&client_id.to_colon_string()));
    relay_msg.hw_addr().inspect(|hw| info!("hw_addr: {:?}", hw));

    if msg.server_id().is_some() {
        info!("Client included a server_id field, ignoring");
        return DhcpV6Response::NoResponse(NoResponseReason::UnexpectedServerId);
    }

    // Rapid Commit option - The client may request the expedited two-message exchange
    // by adding the Rapid Commit option to the first Solicit request
    let msg_type = if msg.rapid_commit() {
        debug!("Solicit 2 message exchange, rapid commit");
        MessageType::Reply
    } else {
        debug!("Solicit 4 message exchange");
        MessageType::Advertise
    };

    let reserved_address = find_reservation(
        reservations,
        leases,
        &config.option1837_extractors,
        relay_msg,
        &client_id,
    );
    match reserved_address {
        Some((reservation, match_info)) => {
            let lease = LeaseV6 {
                first_leased: Instant::now(),
                last_leased: Instant::now(),
                valid: Duration::from_secs(u64::from(VALID_LIFETIME)),
                duid: client_id.clone(),
                mac: None,
            };

            leases.leased_new_v6(&reservation, lease);

            let mut reply = Message::new_with_id(msg_type, msg.xid());
            let opts = reply.opts_mut();

            if matches!(msg_type, MessageType::Reply) {
                // client requested rapid commit
                // https://datatracker.ietf.org/doc/html/rfc8415#section-21.14
                opts.insert(DhcpOption::RapidCommit)
            } else {
                // RFC 8415 Section 21.8: Advertise messages should include a Preference option
                // Value 255 is the maximum preference, causing client to use this server immediately
                opts.insert(DhcpOption::Preference(255));
            }

            // Reply contains IA_NA address and IA_PD prefix as options.
            // These options contain nested options with the actual addresses/prefixes
            // ReplyOptions [IAPD[IAPrefix], IANA[IAAddr]]

            // construct IA_PD information
            if let Some(iapd) = msg.ia_pd() {
                let mut ia_pd_opts = DhcpOptions::new();
                ia_pd_opts.insert(DhcpOption::IAPrefix(IAPrefix {
                    preferred_lifetime: PREFERRED_LIFETIME,
                    valid_lifetime: VALID_LIFETIME,
                    prefix_len: reservation.ipv6_pd.prefix_len(),
                    prefix_ip: reservation.ipv6_pd.addr(),
                    opts: DhcpOptions::new(),
                }));
                // add IA_PD information to Reply message
                opts.insert(DhcpOption::IAPD(IAPD {
                    id: iapd.id,
                    t1: RENEWAL_TIME,
                    t2: REBINDING_TIME,
                    opts: ia_pd_opts,
                }));
            }

            // construct IA_NA information
            if let Some(iana) = msg.ia_na() {
                let mut ia_na_opts = DhcpOptions::new();
                ia_na_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: reservation.ipv6_na,
                    preferred_life: PREFERRED_LIFETIME,
                    valid_life: VALID_LIFETIME,
                    opts: DhcpOptions::new(),
                }));
                // add IA_NA information to Reply message
                opts.insert(DhcpOption::IANA(IANA {
                    id: iana.id,
                    t1: RENEWAL_TIME,
                    t2: REBINDING_TIME,
                    opts: ia_na_opts,
                }));
            }

            opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));
            opts.insert(DhcpOption::ClientId(client_id.bytes));
            DhcpV6Response::Message(ResponseMessage {
                message: reply,
                reservation: Some(reservation),
                reservation_match: Some(match_info),
            })
        }
        None => {
            info!("Solicit request with no reservation for DUID");
            DhcpV6Response::NoResponse(NoResponseReason::NoReservation)
        }
    }
}

#[instrument(skip(config, reservations, leases, msg, relay_msg),
fields(client_id = field::Empty, xid = ?msg.xid()))]
fn handle_renew(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    msg: &Message,
    relay_msg: &RelayMessage,
) -> DhcpV6Response {
    // client is refreshing existing lease, check that the addresses/prefixes sent
    // by the client are the ones we have reserved for them

    // message MUST include a ClientIdentifier option
    let client_id = match msg.client_id() {
        Some(bytes) => shadow_dhcpv6::Duid::from(bytes.to_vec()),
        None => return DhcpV6Response::NoResponse(NoResponseReason::NoClientId),
    };
    Span::current().record("client_id", field::display(&client_id.to_colon_string()));
    relay_msg.hw_addr().inspect(|hw| info!("hw_addr: {:?}", hw));

    // message MUST include ServerIdentifier option AND match this Server's identity
    match msg.server_id() {
        Some(bytes) if bytes == config.v6_server_id.bytes => (),
        Some(_) => return DhcpV6Response::NoResponse(NoResponseReason::WrongServerId),
        None => return DhcpV6Response::NoResponse(NoResponseReason::NoServerId),
    }

    let mut reply = Message::new_with_id(MessageType::Reply, msg.xid());
    let reply_opts = reply.opts_mut();

    let reserved_address = find_reservation(
        reservations,
        leases,
        &config.option1837_extractors,
        relay_msg,
        &client_id,
    );

    let (reservation, match_info) = match reserved_address {
        Some((ref reservation, match_info)) => {
            // check if our server reservation matches what the client sent
            // TODO: should this scan for multiple IANA options?
            if let Some(iana) = msg.ia_na() {
                let mut ia_na_opts = DhcpOptions::new();
                ia_na_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: reservation.ipv6_na,
                    preferred_life: PREFERRED_LIFETIME,
                    valid_life: VALID_LIFETIME,
                    opts: DhcpOptions::new(),
                }));
                // add IA_NA information to Reply message
                reply_opts.insert(DhcpOption::IANA(IANA {
                    id: iana.id,
                    t1: RENEWAL_TIME,
                    t2: REBINDING_TIME,
                    opts: ia_na_opts,
                }));
            }

            if let Some(iapd) = msg.ia_pd() {
                let mut ia_pd_opts = DhcpOptions::new();
                ia_pd_opts.insert(DhcpOption::IAPrefix(IAPrefix {
                    preferred_lifetime: PREFERRED_LIFETIME,
                    valid_lifetime: VALID_LIFETIME,
                    prefix_len: reservation.ipv6_pd.prefix_len(),
                    prefix_ip: reservation.ipv6_pd.addr(),
                    opts: DhcpOptions::new(),
                }));
                // add IA_PD information to Reply message
                reply_opts.insert(DhcpOption::IAPD(IAPD {
                    id: iapd.id,
                    t1: RENEWAL_TIME,
                    t2: REBINDING_TIME,
                    opts: ia_pd_opts,
                }));
            }

            // TODO: redo this
            if reply_opts.iter().count() > 0 {
                let lease = LeaseV6 {
                    first_leased: Instant::now(),
                    last_leased: Instant::now(),
                    valid: Duration::from_secs(u64::from(VALID_LIFETIME)),

                    duid: client_id.clone(),
                    mac: None,
                };
                leases.leased_new_v6(reservation, lease);
            }
            (Some(reservation.clone()), Some(match_info))
        }
        None => {
            // RFC 8415 Section 18.4.2: If the server cannot find a client entry for the IA,
            // the server returns the IA containing no addresses/prefixes with a Status Code
            // option set to NoBinding in the Reply message.
            for opt in msg.opts().iter() {
                match opt {
                    DhcpOption::IANA(iana) => {
                        let mut iana_new = iana.clone();
                        // Zero out lifetimes for any addresses
                        for ia_opt in iana_new.opts.iter_mut() {
                            if let DhcpOption::IAAddr(addr) = ia_opt {
                                addr.valid_life = 0;
                                addr.preferred_life = 0;
                            }
                        }
                        // Add NoBinding status inside the IA option per RFC 8415
                        iana_new
                            .opts
                            .insert(DhcpOption::StatusCode(dhcproto::v6::StatusCode {
                                status: dhcproto::v6::Status::NoBinding,
                                msg: "No binding for this IA".into(),
                            }));
                        reply_opts.insert(DhcpOption::IANA(iana_new));
                    }
                    DhcpOption::IAPD(iapd) => {
                        let mut iapd_new = iapd.clone();
                        // Zero out lifetimes for any prefixes
                        for ia_opt in iapd_new.opts.iter_mut() {
                            if let DhcpOption::IAPrefix(prefix) = ia_opt {
                                prefix.valid_lifetime = 0;
                                prefix.preferred_lifetime = 0;
                            }
                        }
                        // Add NoBinding status inside the IA option per RFC 8415
                        iapd_new
                            .opts
                            .insert(DhcpOption::StatusCode(dhcproto::v6::StatusCode {
                                status: dhcproto::v6::Status::NoBinding,
                                msg: "No binding for this IA".into(),
                            }));
                        reply_opts.insert(DhcpOption::IAPD(iapd_new));
                    }
                    _ => (),
                }
            }
            (None, None)
        }
    };

    reply_opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));
    reply_opts.insert(DhcpOption::ClientId(client_id.bytes));
    DhcpV6Response::Message(ResponseMessage {
        message: reply,
        reservation,
        reservation_match: match_info,
    })
}

#[instrument(skip(config, reservations, leases, msg, relay_msg),
fields(client_id = field::Empty, xid = ?msg.xid()))]
fn handle_request(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    msg: &Message,
    relay_msg: &RelayMessage,
) -> DhcpV6Response {
    // Servers MUST discard any Request messages that:
    // * does not include a Client Identifier
    // * does not include a Server Identifier option
    // * includes a Server Identifier option that does not match this server's DUID
    let client_id = match msg.client_id() {
        Some(bytes) => shadow_dhcpv6::Duid::from(bytes.to_vec()),
        None => return DhcpV6Response::NoResponse(NoResponseReason::NoClientId),
    };
    Span::current().record("client_id", field::display(&client_id.to_colon_string()));
    relay_msg.hw_addr().inspect(|hw| info!("hw_addr: {:?}", hw));

    // message MUST include ServerIdentifier option AND match this Server's identity
    match msg.server_id() {
        Some(bytes) if bytes == config.v6_server_id.bytes => (),
        Some(_) => return DhcpV6Response::NoResponse(NoResponseReason::WrongServerId),
        None => return DhcpV6Response::NoResponse(NoResponseReason::NoServerId),
    }

    let reserved_address = find_reservation(
        reservations,
        leases,
        &config.option1837_extractors,
        relay_msg,
        &client_id,
    );
    match reserved_address {
        Some((reservation, match_info)) => {
            let lease = LeaseV6 {
                first_leased: Instant::now(),
                last_leased: Instant::now(),
                valid: Duration::from_secs(u64::from(VALID_LIFETIME)),
                duid: client_id.clone(),
                mac: None,
            };

            leases.leased_new_v6(&reservation, lease);

            let mut reply = Message::new_with_id(MessageType::Reply, msg.xid());
            let opts = reply.opts_mut();

            // Reply contains IA_NA address and IA_PD prefix as options.
            // These options contain nested options with the actual addresses/prefixes
            // ReplyOptions [IAPD[IAPrefix], IANA[IAAddr]]

            // construct IA_PD information
            if let Some(iapd) = msg.ia_pd() {
                let mut ia_pd_opts = DhcpOptions::new();
                ia_pd_opts.insert(DhcpOption::IAPrefix(IAPrefix {
                    preferred_lifetime: PREFERRED_LIFETIME,
                    valid_lifetime: VALID_LIFETIME,
                    prefix_len: reservation.ipv6_pd.prefix_len(),
                    prefix_ip: reservation.ipv6_pd.addr(),
                    opts: DhcpOptions::new(),
                }));
                // add IA_PD information to Reply message
                opts.insert(DhcpOption::IAPD(IAPD {
                    id: iapd.id,
                    t1: RENEWAL_TIME,
                    t2: REBINDING_TIME,
                    opts: ia_pd_opts,
                }));
            }

            // construct IA_NA information
            if let Some(iana) = msg.ia_na() {
                let mut ia_na_opts = DhcpOptions::new();
                ia_na_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: reservation.ipv6_na,
                    preferred_life: PREFERRED_LIFETIME,
                    valid_life: VALID_LIFETIME,
                    opts: DhcpOptions::new(),
                }));
                // add IA_NA information to Reply message
                opts.insert(DhcpOption::IANA(IANA {
                    id: iana.id,
                    t1: RENEWAL_TIME,
                    t2: REBINDING_TIME,
                    opts: ia_na_opts,
                }));
            }

            opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));
            opts.insert(DhcpOption::ClientId(client_id.bytes));
            DhcpV6Response::Message(ResponseMessage {
                message: reply,
                reservation: Some(reservation),
                reservation_match: Some(match_info),
            })
        }
        None => DhcpV6Response::NoResponse(NoResponseReason::NoReservation),
    }
}

/// Handle Rebind messages per RFC 8415 Section 18.4.5
///
/// Rebind is similar to Renew, but the client sends it to any available server
/// (not specifically to the server that originally assigned the lease).
#[instrument(skip(config, reservations, leases, msg, relay_msg),
fields(client_id = field::Empty, xid = ?msg.xid()))]
fn handle_rebind(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    msg: &Message,
    relay_msg: &RelayMessage,
) -> DhcpV6Response {
    // Message MUST include a ClientIdentifier option
    let client_id = match msg.client_id() {
        Some(bytes) => shadow_dhcpv6::Duid::from(bytes.to_vec()),
        None => return DhcpV6Response::NoResponse(NoResponseReason::NoClientId),
    };
    Span::current().record("client_id", field::display(&client_id.to_colon_string()));
    relay_msg.hw_addr().inspect(|hw| info!("hw_addr: {:?}", hw));

    // RFC 8415 Section 18.4.5: Rebind messages should NOT contain a Server Identifier
    // If present, we can still process it but it's unusual
    if msg.server_id().is_some() {
        debug!("Rebind message contains Server ID (unusual but allowed)");
    }

    let mut reply = Message::new_with_id(MessageType::Reply, msg.xid());
    let reply_opts = reply.opts_mut();

    let reserved_address = find_reservation(
        reservations,
        leases,
        &config.option1837_extractors,
        relay_msg,
        &client_id,
    );

    let (reservation, match_info) = match reserved_address {
        Some((ref reservation, match_info)) => {
            if let Some(iana) = msg.ia_na() {
                let mut ia_na_opts = DhcpOptions::new();
                ia_na_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: reservation.ipv6_na,
                    preferred_life: PREFERRED_LIFETIME,
                    valid_life: VALID_LIFETIME,
                    opts: DhcpOptions::new(),
                }));
                reply_opts.insert(DhcpOption::IANA(IANA {
                    id: iana.id,
                    t1: RENEWAL_TIME,
                    t2: REBINDING_TIME,
                    opts: ia_na_opts,
                }));
            }

            if let Some(iapd) = msg.ia_pd() {
                let mut ia_pd_opts = DhcpOptions::new();
                ia_pd_opts.insert(DhcpOption::IAPrefix(IAPrefix {
                    preferred_lifetime: PREFERRED_LIFETIME,
                    valid_lifetime: VALID_LIFETIME,
                    prefix_len: reservation.ipv6_pd.prefix_len(),
                    prefix_ip: reservation.ipv6_pd.addr(),
                    opts: DhcpOptions::new(),
                }));
                reply_opts.insert(DhcpOption::IAPD(IAPD {
                    id: iapd.id,
                    t1: RENEWAL_TIME,
                    t2: REBINDING_TIME,
                    opts: ia_pd_opts,
                }));
            }

            if reply_opts.iter().count() > 0 {
                let lease = LeaseV6 {
                    first_leased: Instant::now(),
                    last_leased: Instant::now(),
                    valid: Duration::from_secs(u64::from(VALID_LIFETIME)),
                    duid: client_id.clone(),
                    mac: None,
                };
                leases.leased_new_v6(reservation, lease);
            }
            (Some(reservation.clone()), Some(match_info))
        }
        None => {
            // RFC 8415 Section 18.4.5: Same as Renew - return IAs with NoBinding status
            for opt in msg.opts().iter() {
                match opt {
                    DhcpOption::IANA(iana) => {
                        let mut iana_new = iana.clone();
                        for ia_opt in iana_new.opts.iter_mut() {
                            if let DhcpOption::IAAddr(addr) = ia_opt {
                                addr.valid_life = 0;
                                addr.preferred_life = 0;
                            }
                        }
                        iana_new
                            .opts
                            .insert(DhcpOption::StatusCode(dhcproto::v6::StatusCode {
                                status: dhcproto::v6::Status::NoBinding,
                                msg: "No binding for this IA".into(),
                            }));
                        reply_opts.insert(DhcpOption::IANA(iana_new));
                    }
                    DhcpOption::IAPD(iapd) => {
                        let mut iapd_new = iapd.clone();
                        for ia_opt in iapd_new.opts.iter_mut() {
                            if let DhcpOption::IAPrefix(prefix) = ia_opt {
                                prefix.valid_lifetime = 0;
                                prefix.preferred_lifetime = 0;
                            }
                        }
                        iapd_new
                            .opts
                            .insert(DhcpOption::StatusCode(dhcproto::v6::StatusCode {
                                status: dhcproto::v6::Status::NoBinding,
                                msg: "No binding for this IA".into(),
                            }));
                        reply_opts.insert(DhcpOption::IAPD(iapd_new));
                    }
                    _ => (),
                }
            }
            (None, None)
        }
    };

    reply_opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));
    reply_opts.insert(DhcpOption::ClientId(client_id.bytes));
    DhcpV6Response::Message(ResponseMessage {
        message: reply,
        reservation,
        reservation_match: match_info,
    })
}

pub fn handle_message(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    msg: &Message,
    relay_msg: &RelayMessage,
) -> DhcpV6Response {
    match msg.msg_type() {
        // A client sends a Solicit message to locate servers.
        // https://datatracker.ietf.org/doc/html/rfc8415#section-16.2
        // Four-message exchange - Solicit -> Advertisement -> Request -> Reply
        // Two-message exchange (rapid commit) - Solicit -> Reply
        MessageType::Solicit => handle_solicit(config, reservations, leases, msg, relay_msg),
        // Servers always discard Advertise
        MessageType::Advertise => DhcpV6Response::NoResponse(NoResponseReason::Discarded),
        // A client sends a Request as part of the 4 message exchange to receive an initial address/prefix
        // https://datatracker.ietf.org/doc/html/rfc8415#section-16.4
        MessageType::Request => handle_request(config, reservations, leases, msg, relay_msg),
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
        MessageType::Renew => handle_renew(config, reservations, leases, msg, relay_msg),
        // RFC 8415 Section 18.4.5: Rebind is like Renew but sent to any server
        // when the client can't reach the original server
        MessageType::Rebind => handle_rebind(config, reservations, leases, msg, relay_msg),
        _ => {
            error!(
                "MessageType `{:?}` not implemented by ddhcpv6",
                msg.msg_type()
            );
            DhcpV6Response::NoResponse(NoResponseReason::Discarded)
        }
    }
}
