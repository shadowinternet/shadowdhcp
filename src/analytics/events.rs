use advmac::MacAddr6;
use compact_str::CompactString;
use dhcproto::v4;
use dhcproto::v6::{self, MessageType};
use ipnet::Ipv6Net;
use serde::Serialize;
use shadow_dhcpv6::{RelayAgentInformationExt, Reservation};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::v4::extensions::ShadowMessageExtV4;
use crate::v6::extensions::{ShadowMessageExtV6, ShadowRelayMessageExtV6};

#[derive(Serialize)]
#[serde(tag = "ip_version")]
pub enum DhcpEvent {
    #[serde(rename = "v6")]
    V6(DhcpEventV6),
    #[serde(rename = "v4")]
    V4(DhcpEventV4),
}

/// DHCPv4 event for analytics - enables v4/v6 correlation via mac_address
#[derive(Serialize)]
pub struct DhcpEventV4 {
    pub timestamp_ms: u64,
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
        CompactString::from_utf8(bytes.to_vec()).ok()
    }

    pub fn success(
        msg: &v4::Message,
        relay_addr: Ipv4Addr,
        reservation: Option<&Reservation>,
    ) -> Self {
        // Extract option82 from the request message
        let relay_info = msg.relay_agent_information();
        let res_option82 = reservation.and_then(|r| r.option82.as_ref());

        Self {
            timestamp_ms: now(),
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
            success: true,
            failure_reason: None,
        }
    }

    pub fn failed(msg: &v4::Message, relay_addr: Ipv4Addr, reason: &'static str) -> Self {
        let relay_info = msg.relay_agent_information();

        Self {
            timestamp_ms: now(),
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
            success: false,
            failure_reason: Some(reason),
        }
    }
}

/// DHCPv6 event for analytics
///
/// Field types chosen for ClickHouse compatibility:
/// - IPv6 addresses → ClickHouse IPv6
/// - IPv4 addresses → ClickHouse IPv4
/// - MAC addresses → String (enables JOIN with v4 events)
/// - Timestamps as u64 milliseconds → ClickHouse DateTime64(3)
#[derive(Serialize)]
pub struct DhcpEventV6 {
    pub timestamp_ms: u64,
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

    fn format_duid(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn success(
        input_msg: &v6::Message,
        relay_msg: &v6::RelayMessage,
        relay_addr: Ipv6Addr,
        reservation: Option<&Reservation>,
    ) -> Self {
        let option1837 = relay_msg.option1837();
        let res_option1837 = reservation.and_then(|r| r.option1837.as_ref());

        DhcpEventV6 {
            timestamp_ms: now(),
            message_type: Self::message_type_str(input_msg.msg_type()),
            xid: format!(
                "{:02x}{:02x}{:02x}",
                input_msg.xid()[0],
                input_msg.xid()[1],
                input_msg.xid()[2]
            ),
            relay_addr,
            relay_link_addr: relay_msg.link_addr(),
            relay_peer_addr: relay_msg.peer_addr(),
            // Request data
            mac_address: relay_msg.hw_addr(),
            client_id: input_msg.client_id().map(Self::format_duid),
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
                .map(|d| Self::format_duid(&d.bytes)),
            reservation_option1837_interface: res_option1837
                .and_then(|o| o.interface.as_ref().map(|s| s.to_string())),
            reservation_option1837_remote: res_option1837
                .and_then(|o| o.remote.as_ref().map(|s| s.to_string())),
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
            timestamp_ms: now(),
            message_type: Self::message_type_str(input_msg.msg_type()),
            xid: format!(
                "{:02x}{:02x}{:02x}",
                input_msg.xid()[0],
                input_msg.xid()[1],
                input_msg.xid()[2]
            ),
            relay_addr,
            relay_link_addr: relay_msg.link_addr(),
            relay_peer_addr: relay_msg.peer_addr(),
            // Request data
            mac_address: relay_msg.hw_addr(),
            client_id: input_msg.client_id().map(Self::format_duid),
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
            success: false,
            failure_reason: Some(reason),
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
