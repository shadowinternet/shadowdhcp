use crate::types::{Duid, Reservation};
use advmac::MacAddr6;
use compact_str::CompactString;
use dhcproto::v4;
use dhcproto::v6::{self, MessageType};
use ipnet::Ipv6Net;
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::v4::extensions::{RelayAgentInformationExt, ShadowMessageExtV4};
use crate::v6::extensions::{ShadowMessageExtV6, ShadowRelayMessageExtV6};

/// Metadata about how a reservation was matched
#[derive(Debug, Clone, Copy)]
pub struct ReservationMatch {
    /// The method used to find the reservation: "mac", "duid", "option82", "option1837"
    pub method: &'static str,
    /// The extractor function name that succeeded (for option82/option1837 matches)
    pub extractor: Option<&'static str>,
}

impl ReservationMatch {
    pub fn mac(extractor: &'static str) -> Self {
        Self {
            method: "mac",
            extractor: Some(extractor),
        }
    }

    pub fn duid() -> Self {
        Self {
            method: "duid",
            extractor: None,
        }
    }

    pub fn option82(extractor: &'static str) -> Self {
        Self {
            method: "option82",
            extractor: Some(extractor),
        }
    }

    pub fn option1837(extractor: &'static str) -> Self {
        Self {
            method: "option1837",
            extractor: Some(extractor),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "ip_version")]
pub enum DhcpEvent {
    #[serde(rename = "v6")]
    V6(DhcpEventV6),
    #[serde(rename = "v4")]
    V4(DhcpEventV4),
}

/// DHCPv4 event for analytics - enables v4/v6 correlation via mac_address
#[derive(Clone, Serialize)]
pub struct DhcpEventV4 {
    /// Unix milliseconds. ClickHouse parses the integer directly into a
    /// `DateTime64(3)` column.
    pub timestamp: u64,
    pub message_type: Option<&'static str>,
    pub relay_addr: Ipv4Addr,

    // === Request data (from client/relay) ===
    pub mac_address: Option<MacAddr6>,
    pub option82_circuit: Option<CompactString>,
    pub option82_remote: Option<CompactString>,
    pub option82_subscriber: Option<CompactString>,

    // === Reservation data (what matched) ===
    pub reservation_ipv4: Option<Ipv4Addr>,
    pub reservation_mac: Option<MacAddr6>,
    pub reservation_option82_circuit: Option<CompactString>,
    pub reservation_option82_remote: Option<CompactString>,
    pub reservation_option82_subscriber: Option<CompactString>,

    // === Match metadata ===
    /// How the reservation was matched: "mac", "option82"
    pub match_method: Option<&'static str>,
    /// Which extractor function was used (for option82 matches)
    pub extractor_used: Option<&'static str>,

    pub success: bool,
    pub failure_reason: Option<&'static str>,
}

impl DhcpEventV4 {
    fn message_type_str(msg_type: &v4::MessageType) -> &'static str {
        match msg_type {
            v4::MessageType::Ack => "Ack",
            v4::MessageType::Discover => "Discover",
            v4::MessageType::Offer => "Offer",
            v4::MessageType::Request => "Request",
            v4::MessageType::Decline => "Decline",
            v4::MessageType::Nak => "Nak",
            v4::MessageType::Release => "Release",
            _ => "Unknown",
        }
    }

    fn bytes_to_compact_string(bytes: &[u8]) -> Option<CompactString> {
        CompactString::from_utf8(bytes).ok()
    }

    pub fn success(
        msg: &v4::Message,
        relay_addr: Ipv4Addr,
        reservation: Option<&Reservation>,
        reservation_match: Option<ReservationMatch>,
    ) -> Self {
        // Extract option82 from the request message
        let relay_info = msg.relay_agent_information();
        let res_option82 = reservation.and_then(|r| r.option82.as_ref());

        Self {
            timestamp: now(),
            message_type: msg.message_type().map(Self::message_type_str),
            relay_addr,
            // Request data
            mac_address: MacAddr6::try_from(msg.chaddr()).ok(),
            option82_circuit: relay_info
                .and_then(|r| r.circuit_id())
                .and_then(|b| Self::bytes_to_compact_string(&b)),
            option82_remote: relay_info
                .and_then(|r| r.remote_id())
                .and_then(|b| Self::bytes_to_compact_string(&b)),
            option82_subscriber: relay_info
                .and_then(|r| r.subscriber_id())
                .and_then(|b| Self::bytes_to_compact_string(&b)),
            // Reservation data
            reservation_ipv4: reservation.map(|r| r.ipv4),
            reservation_mac: reservation.and_then(|r| r.mac),
            reservation_option82_circuit: res_option82.and_then(|o| o.circuit.clone()),
            reservation_option82_remote: res_option82.and_then(|o| o.remote.clone()),
            reservation_option82_subscriber: res_option82.and_then(|o| o.subscriber.clone()),
            // Match metadata
            match_method: reservation_match.map(|m| m.method),
            extractor_used: reservation_match.and_then(|m| m.extractor),
            success: true,
            failure_reason: None,
        }
    }

    pub fn failed(msg: &v4::Message, relay_addr: Ipv4Addr, reason: &'static str) -> Self {
        let relay_info = msg.relay_agent_information();

        Self {
            timestamp: now(),
            message_type: msg.message_type().map(Self::message_type_str),
            relay_addr,
            // Request data
            mac_address: MacAddr6::try_from(msg.chaddr()).ok(),
            option82_circuit: relay_info
                .and_then(|r| r.circuit_id())
                .and_then(|b| Self::bytes_to_compact_string(&b)),
            option82_remote: relay_info
                .and_then(|r| r.remote_id())
                .and_then(|b| Self::bytes_to_compact_string(&b)),
            option82_subscriber: relay_info
                .and_then(|r| r.subscriber_id())
                .and_then(|b| Self::bytes_to_compact_string(&b)),
            // No reservation
            reservation_ipv4: None,
            reservation_mac: None,
            reservation_option82_circuit: None,
            reservation_option82_remote: None,
            reservation_option82_subscriber: None,
            // No match
            match_method: None,
            extractor_used: None,
            success: false,
            failure_reason: Some(reason),
        }
    }

    /// Datagram arrived but could not be decoded. All we know is who relayed
    /// it and when; `message_type`/`mac_address` are nullable in the schema
    /// for this case.
    pub fn parse_error(relay_addr: Ipv4Addr) -> Self {
        Self {
            timestamp: now(),
            message_type: None,
            relay_addr,
            mac_address: None,
            option82_circuit: None,
            option82_remote: None,
            option82_subscriber: None,
            reservation_ipv4: None,
            reservation_mac: None,
            reservation_option82_circuit: None,
            reservation_option82_remote: None,
            reservation_option82_subscriber: None,
            match_method: None,
            extractor_used: None,
            success: false,
            failure_reason: Some("ParseError"),
        }
    }

    /// A response was built but never reached the wire (encode or send
    /// failure). Keeps the reservation/match data so the transaction stays
    /// queryable by subscriber.
    pub fn send_failed(
        msg: &v4::Message,
        relay_addr: Ipv4Addr,
        reservation: Option<&Reservation>,
        reservation_match: Option<ReservationMatch>,
        reason: &'static str,
    ) -> Self {
        let mut event = Self::success(msg, relay_addr, reservation, reservation_match);
        event.success = false;
        event.failure_reason = Some(reason);
        event
    }
}

/// DHCPv6 event for analytics
///
/// Field types chosen for ClickHouse compatibility:
/// - IPv6 addresses → ClickHouse IPv6
/// - IPv4 addresses → ClickHouse IPv4
/// - MAC addresses → String (enables JOIN with v4 events)
#[derive(Clone, Serialize)]
pub struct DhcpEventV6 {
    /// Unix milliseconds. ClickHouse parses the integer directly into a
    /// `DateTime64(3)` column.
    pub timestamp: u64,
    pub message_type: &'static str,
    /// Transaction ID from the client (hex string)
    pub xid: String,
    pub relay_addr: Ipv6Addr,
    pub relay_link_addr: Ipv6Addr,
    pub relay_peer_addr: Ipv6Addr,

    // === Request data (from client/relay) ===
    /// Client's MAC address from relay
    pub mac_address: Option<MacAddr6>,
    /// Client DUID as hex string
    pub client_id: Option<String>,
    /// Option 18: Interface-ID from relay agent
    pub option1837_interface: Option<String>,
    /// Option 37: Remote-ID from relay agent
    pub option1837_remote: Option<String>,
    pub requested_ipv6_na: Option<Ipv6Addr>,
    pub requested_ipv6_pd: Option<Ipv6Net>,

    // === Reservation data (what matched) ===
    pub reservation_ipv6_na: Option<Ipv6Addr>,
    pub reservation_ipv6_pd: Option<Ipv6Net>,
    pub reservation_ipv4: Option<Ipv4Addr>,
    pub reservation_mac: Option<MacAddr6>,
    pub reservation_duid: Option<String>,
    pub reservation_option1837_interface: Option<String>,
    pub reservation_option1837_remote: Option<String>,

    // === Match metadata ===
    /// How the reservation was matched: "mac", "duid", "option1837"
    pub match_method: Option<&'static str>,
    /// Which extractor function was used (for option1837 matches)
    pub extractor_used: Option<&'static str>,

    pub success: bool,
    pub failure_reason: Option<&'static str>,
}

impl DhcpEventV6 {
    fn message_type_str(msg_type: MessageType) -> &'static str {
        match msg_type {
            MessageType::Solicit => "Solicit",
            MessageType::Advertise => "Advertise",
            MessageType::Request => "Request",
            MessageType::Confirm => "Confirm",
            MessageType::Renew => "Renew",
            MessageType::Rebind => "Rebind",
            MessageType::Reply => "Reply",
            MessageType::Release => "Release",
            MessageType::Decline => "Decline",
            MessageType::Reconfigure => "Reconfigure",
            MessageType::InformationRequest => "InformationRequest",
            MessageType::RelayForw => "RelayForw",
            MessageType::RelayRepl => "RelayRepl",
            _ => "Unknown",
        }
    }

    pub fn success(
        input_msg: &v6::Message,
        relay_msg: &v6::RelayMessage,
        relay_addr: Ipv6Addr,
        reservation: Option<&Reservation>,
        reservation_match: Option<ReservationMatch>,
    ) -> Self {
        let option1837 = relay_msg.option1837();
        let res_option1837 = reservation.and_then(|r| r.option1837.as_ref());

        DhcpEventV6 {
            timestamp: now(),
            message_type: Self::message_type_str(input_msg.msg_type()),
            xid: format!(
                "{:02x}{:02x}{:02x}",
                input_msg.xid().first().copied().unwrap_or(0),
                input_msg.xid().get(1).copied().unwrap_or(0),
                input_msg.xid().get(2).copied().unwrap_or(0)
            ),
            relay_addr,
            relay_link_addr: relay_msg.link_addr(),
            relay_peer_addr: relay_msg.peer_addr(),
            // Request data
            mac_address: relay_msg.hw_addr(),
            client_id: input_msg
                .client_id()
                .and_then(|bytes| Duid::new(bytes.to_vec()))
                .map(|d| d.to_string()),
            option1837_interface: option1837
                .as_ref()
                .and_then(|o| o.interface.as_ref().map(|s| s.to_string())),
            option1837_remote: option1837
                .as_ref()
                .and_then(|o| o.remote.as_ref().map(|s| s.to_string())),
            requested_ipv6_na: input_msg.ia_na_address(),
            requested_ipv6_pd: input_msg.ia_pd_prefix(),
            // Reservation data
            reservation_ipv6_na: reservation.map(|r| r.ipv6_na),
            reservation_ipv6_pd: reservation.map(|r| r.ipv6_pd),
            reservation_ipv4: reservation.map(|r| r.ipv4),
            reservation_mac: reservation.and_then(|r| r.mac),
            reservation_duid: reservation
                .and_then(|r| r.duid.as_ref())
                .map(|d| d.to_string()),
            reservation_option1837_interface: res_option1837
                .and_then(|o| o.interface.as_ref().map(|s| s.to_string())),
            reservation_option1837_remote: res_option1837
                .and_then(|o| o.remote.as_ref().map(|s| s.to_string())),
            // Match metadata
            match_method: reservation_match.map(|m| m.method),
            extractor_used: reservation_match.and_then(|m| m.extractor),
            success: true,
            failure_reason: None,
        }
    }

    pub fn failed(
        input_msg: &v6::Message,
        relay_msg: &v6::RelayMessage,
        relay_addr: Ipv6Addr,
        reason: &'static str,
    ) -> DhcpEventV6 {
        let option1837 = relay_msg.option1837();

        DhcpEventV6 {
            timestamp: now(),
            message_type: Self::message_type_str(input_msg.msg_type()),
            xid: format!(
                "{:02x}{:02x}{:02x}",
                input_msg.xid().first().copied().unwrap_or(0),
                input_msg.xid().get(1).copied().unwrap_or(0),
                input_msg.xid().get(2).copied().unwrap_or(0)
            ),
            relay_addr,
            relay_link_addr: relay_msg.link_addr(),
            relay_peer_addr: relay_msg.peer_addr(),
            // Request data
            mac_address: relay_msg.hw_addr(),
            client_id: input_msg
                .client_id()
                .and_then(|bytes| Duid::new(bytes.to_vec()))
                .map(|d| d.to_string()),
            option1837_interface: option1837
                .as_ref()
                .and_then(|o| o.interface.as_ref().map(|s| s.to_string())),
            option1837_remote: option1837
                .as_ref()
                .and_then(|o| o.remote.as_ref().map(|s| s.to_string())),
            requested_ipv6_na: input_msg.ia_na_address(),
            requested_ipv6_pd: input_msg.ia_pd_prefix(),
            // No reservation
            reservation_ipv6_na: None,
            reservation_ipv6_pd: None,
            reservation_ipv4: None,
            reservation_mac: None,
            reservation_duid: None,
            reservation_option1837_interface: None,
            reservation_option1837_remote: None,
            // No match
            match_method: None,
            extractor_used: None,
            success: false,
            failure_reason: Some(reason),
        }
    }

    /// Datagram arrived but could not be decoded as a relay message. All we
    /// know is who relayed it and when; the non-nullable columns take
    /// sentinels (`Unknown`, empty xid, `::`).
    pub fn parse_error(relay_addr: Ipv6Addr) -> Self {
        Self {
            timestamp: now(),
            message_type: "Unknown",
            xid: String::new(),
            relay_addr,
            relay_link_addr: Ipv6Addr::UNSPECIFIED,
            relay_peer_addr: Ipv6Addr::UNSPECIFIED,
            mac_address: None,
            client_id: None,
            option1837_interface: None,
            option1837_remote: None,
            requested_ipv6_na: None,
            requested_ipv6_pd: None,
            reservation_ipv6_na: None,
            reservation_ipv6_pd: None,
            reservation_ipv4: None,
            reservation_mac: None,
            reservation_duid: None,
            reservation_option1837_interface: None,
            reservation_option1837_remote: None,
            match_method: None,
            extractor_used: None,
            success: false,
            failure_reason: Some("ParseError"),
        }
    }

    /// Relay message decoded but carried no usable inner client message
    /// (missing RelayMsg option, or a nested relay chain we don't support).
    /// The relay wrapper still yields link/peer addresses, MAC, and
    /// option 18/37 identifiers.
    pub fn relay_failed(
        relay_msg: &v6::RelayMessage,
        relay_addr: Ipv6Addr,
        reason: &'static str,
    ) -> Self {
        let option1837 = relay_msg.option1837();

        Self {
            timestamp: now(),
            message_type: "Unknown",
            xid: String::new(),
            relay_addr,
            relay_link_addr: relay_msg.link_addr(),
            relay_peer_addr: relay_msg.peer_addr(),
            mac_address: relay_msg.hw_addr(),
            client_id: None,
            option1837_interface: option1837
                .as_ref()
                .and_then(|o| o.interface.as_ref().map(|s| s.to_string())),
            option1837_remote: option1837
                .as_ref()
                .and_then(|o| o.remote.as_ref().map(|s| s.to_string())),
            requested_ipv6_na: None,
            requested_ipv6_pd: None,
            reservation_ipv6_na: None,
            reservation_ipv6_pd: None,
            reservation_ipv4: None,
            reservation_mac: None,
            reservation_duid: None,
            reservation_option1837_interface: None,
            reservation_option1837_remote: None,
            match_method: None,
            extractor_used: None,
            success: false,
            failure_reason: Some(reason),
        }
    }

    /// A response was built but never reached the wire (encode or send
    /// failure). Keeps the reservation/match data
    pub fn send_failed(
        input_msg: &v6::Message,
        relay_msg: &v6::RelayMessage,
        relay_addr: Ipv6Addr,
        reservation: Option<&Reservation>,
        reservation_match: Option<ReservationMatch>,
        reason: &'static str,
    ) -> Self {
        let mut event = Self::success(
            input_msg,
            relay_msg,
            relay_addr,
            reservation,
            reservation_match,
        );
        event.success = false;
        event.failure_reason = Some(reason);
        event
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
