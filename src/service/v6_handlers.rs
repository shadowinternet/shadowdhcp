// src/service/v6_handlers.rs

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dhcproto::v6::{
    DhcpOption, DhcpOptions, IAAddr, IAPrefix, Message, MessageType, RelayMessage,
    RelayMessageData, IANA, IAPD,
};
use dhcproto::Encodable;
use tracing::{info, instrument};

use crate::config::Config;
use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;
use crate::service::dhcp::{DhcpError, DhcpServiceResponse};
use crate::types::{DhcpResponse, Duid, LeaseV6, RequestOutcome, V6Request};

const PREFERRED_LIFETIME: u32 = 3600;
const VALID_LIFETIME: u32 = 7200;

#[instrument(skip_all, fields(
    client_duid = %Duid::from(req.client_duid.clone()),
    msg_type = ?req.inner_message.msg_type()
))]
pub fn handle_v6(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    req: V6Request,
    source: SocketAddr,
) -> Result<DhcpServiceResponse, DhcpError> {
    let client_duid = Duid::from(req.client_duid.clone());

    let result = match req.inner_message.msg_type() {
        MessageType::Solicit => process_solicit(config, reservations, leases, &req, &client_duid),
        MessageType::Request => process_request(config, reservations, leases, &req, &client_duid),
        MessageType::Renew => process_renew(config, reservations, leases, &req, &client_duid),
        msg_type => {
            info!(?msg_type, "Unhandled message type");
            return Ok(DhcpServiceResponse {
                response: None,
                outcome: RequestOutcome {
                    success: false,
                    failure_reason: Some("unhandled_message_type"),
                    message_type: Some(message_type_str(req.inner_message.msg_type())),
                    ..Default::default()
                },
            });
        }
    };

    match result {
        Ok((response_msg, outcome)) => {
            // Wrap in RelayReply
            let relay_reply = wrap_in_relay_reply(&req.relay_message, response_msg);
            let encoded = relay_reply
                .to_vec()
                .map_err(|e| DhcpError::Internal(e.to_string()))?;

            Ok(DhcpServiceResponse {
                response: Some(DhcpResponse {
                    destination: source,
                    payload: encoded,
                }),
                outcome,
            })
        }
        Err(outcome) => Ok(DhcpServiceResponse {
            response: None,
            outcome,
        }),
    }
}

/// Process solicit - returns Ok((Message, Outcome)) on success, Err(Outcome) on failure
fn process_solicit(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    req: &V6Request,
    client_duid: &Duid,
) -> Result<(Message, RequestOutcome), RequestOutcome> {
    let msg = &req.inner_message;

    // Validate: must not include server ID
    if msg
        .opts()
        .iter()
        .any(|o| matches!(o, DhcpOption::ServerId(_)))
    {
        return Err(RequestOutcome {
            success: false,
            failure_reason: Some("unexpected_server_id"),
            message_type: Some("solicit"),
            ..Default::default()
        });
    }

    // Find reservation
    let reservation =
        find_reservation(reservations, leases, req, client_duid).ok_or_else(|| RequestOutcome {
            success: false,
            failure_reason: Some("no_reservation"),
            message_type: Some("solicit"),
            ..Default::default()
        })?;

    // Determine response type (rapid commit or not)
    let is_rapid_commit = msg
        .opts()
        .iter()
        .any(|o| matches!(o, DhcpOption::RapidCommit));
    let msg_type = if is_rapid_commit {
        MessageType::Reply
    } else {
        MessageType::Advertise
    };

    // Build response
    let mut reply = Message::new_with_id(msg_type, msg.xid());
    let opts = reply.opts_mut();

    if is_rapid_commit {
        opts.insert(DhcpOption::RapidCommit);
    }

    // Add IA_NA if requested
    if msg.opts().iter().any(|o| matches!(o, DhcpOption::IANA(_))) {
        let mut ia_na_opts = DhcpOptions::new();
        ia_na_opts.insert(DhcpOption::IAAddr(IAAddr {
            addr: reservation.ipv6_na,
            preferred_life: PREFERRED_LIFETIME,
            valid_life: VALID_LIFETIME,
            opts: DhcpOptions::new(),
        }));
        opts.insert(DhcpOption::IANA(IANA {
            id: 1,
            t1: PREFERRED_LIFETIME,
            t2: VALID_LIFETIME,
            opts: ia_na_opts,
        }));
    }

    // Add IA_PD if requested
    if msg.opts().iter().any(|o| matches!(o, DhcpOption::IAPD(_))) {
        let mut ia_pd_opts = DhcpOptions::new();
        ia_pd_opts.insert(DhcpOption::IAPrefix(IAPrefix {
            preferred_lifetime: PREFERRED_LIFETIME,
            valid_lifetime: VALID_LIFETIME,
            prefix_len: reservation.ipv6_pd.prefix_len(),
            prefix_ip: reservation.ipv6_pd.addr(),
            opts: DhcpOptions::new(),
        }));
        opts.insert(DhcpOption::IAPD(IAPD {
            id: 1,
            t1: PREFERRED_LIFETIME,
            t2: VALID_LIFETIME,
            opts: ia_pd_opts,
        }));
    }

    opts.insert(DhcpOption::ServerId(config.v6_server_id.bytes.clone()));
    opts.insert(DhcpOption::ClientId(client_duid.bytes.clone()));

    // Record lease
    leases.leased_new_v6(
        &reservation,
        LeaseV6 {
            first_leased: Instant::now(),
            last_leased: Instant::now(),
            valid: Duration::from_secs(u64::from(VALID_LIFETIME)),
            duid: client_duid.clone(),
            mac: req.hw_addr,
        },
    );

    let outcome = RequestOutcome {
        success: true,
        failure_reason: None,
        assigned_v6_na: Some(reservation.ipv6_na),
        assigned_v6_pd: Some(reservation.ipv6_pd),
        message_type: Some("solicit"),
        reservation_id: reservation.mac.map(|m| m.to_string()),
        ..Default::default()
    };

    Ok((reply, outcome))
}

fn process_request(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    req: &V6Request,
    client_duid: &Duid,
) -> Result<(Message, RequestOutcome), RequestOutcome> {
    // Similar structure to process_solicit but validates server ID matches
    let msg = &req.inner_message;

    // Must include server ID matching us
    let server_id_matches = msg.opts().iter().any(|o| match o {
        DhcpOption::ServerId(id) => id == &config.v6_server_id.bytes,
        _ => false,
    });

    if !server_id_matches {
        return Err(RequestOutcome {
            success: false,
            failure_reason: Some("server_id_mismatch"),
            message_type: Some("request"),
            ..Default::default()
        });
    }

    let reservation =
        find_reservation(reservations, leases, req, client_duid).ok_or_else(|| RequestOutcome {
            success: false,
            failure_reason: Some("no_reservation"),
            message_type: Some("request"),
            ..Default::default()
        })?;

    // Build reply (similar to solicit but always Reply type)
    let mut reply = Message::new_with_id(MessageType::Reply, msg.xid());
    // ... populate options same as solicit ...

    let outcome = RequestOutcome {
        success: true,
        assigned_v6_na: Some(reservation.ipv6_na),
        assigned_v6_pd: Some(reservation.ipv6_pd),
        message_type: Some("request"),
        ..Default::default()
    };

    Ok((reply, outcome))
}

fn process_renew(
    config: &Config,
    reservations: &ReservationDb,
    leases: &LeaseDb,
    req: &V6Request,
    client_duid: &Duid,
) -> Result<(Message, RequestOutcome), RequestOutcome> {
    // Similar validation and response building
    todo!()
}

fn find_reservation(
    reservations: &ReservationDb,
    leases: &LeaseDb,
    req: &V6Request,
    client_duid: &Duid,
) -> Option<Arc<crate::Reservation>> {
    reservations
        .by_duid(client_duid)
        .or_else(|| req.hw_addr.and_then(|mac| reservations.by_mac(mac)))
        .or_else(|| {
            req.hw_addr.and_then(|mac| {
                leases
                    .get_opt82_by_mac(&mac)
                    .and_then(|opt82| reservations.by_opt82(&opt82))
            })
        })
}

fn wrap_in_relay_reply(original: &RelayMessage, inner: Message) -> RelayMessage {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::RelayMsg(RelayMessageData::Message(inner)));

    // Copy interface-id if present
    if let Some(interface_id) = original
        .opts
        .iter()
        .find(|o| matches!(o, DhcpOption::InterfaceId(_)))
    {
        opts.insert(interface_id.clone());
    }

    RelayMessage {
        msg_type: MessageType::RelayRepl,
        hop_count: original.hop_count,
        link_addr: original.link_addr,
        peer_addr: original.peer_addr,
        opts,
    }
}

fn message_type_str(mt: MessageType) -> &'static str {
    match mt {
        MessageType::Solicit => "solicit",
        MessageType::Advertise => "advertise",
        MessageType::Request => "request",
        MessageType::Confirm => "confirm",
        MessageType::Renew => "renew",
        MessageType::Rebind => "rebind",
        MessageType::Reply => "reply",
        MessageType::Release => "release",
        MessageType::Decline => "decline",
        MessageType::Reconfigure => "reconfigure",
        MessageType::InformationRequest => "information_request",
        MessageType::RelayForw => "relay_forw",
        MessageType::RelayRepl => "relay_repl",
        _ => "unknown",
    }
}
