use advmac::MacAddr6;
use compact_str::CompactString;
use dhcproto::v4;
use dhcproto::v6::{self, MessageType};
use ipnet::Ipv6Net;
use serde::Serialize;
use shadow_dhcpv6::Reservation;
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
    pub mac_address: Option<MacAddr6>,
    pub option82_circuit: Option<CompactString>,
    pub option82_remote: Option<CompactString>,
    pub option82_subscriber: Option<CompactString>,
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub relay_addr: Ipv4Addr,
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
    pub fn success(
        msg: &v4::Message,
        relay_addr: Ipv4Addr,
        reservation: Option<&Reservation>,
    ) -> Self {
        let option82 = reservation.and_then(|r| r.option82.clone());
        Self {
            timestamp_ms: now(),
            message_type: msg.message_type().map(Self::message_type_str),
            mac_address: MacAddr6::try_from(msg.chaddr()).ok(),
            option82_circuit: option82.as_ref().and_then(|opt| opt.circuit.clone()),
            option82_remote: option82.as_ref().and_then(|opt| opt.remote.clone()),
            option82_subscriber: option82.as_ref().and_then(|opt| opt.subscriber.clone()),
            assigned_ipv4: reservation.map(|r| r.ipv4),
            relay_addr,
            success: true,
            failure_reason: None,
        }
    }

    pub fn failed(msg: &v4::Message, relay_addr: Ipv4Addr, reason: &'static str) -> Self {
        Self {
            timestamp_ms: now(),
            message_type: msg.message_type().map(Self::message_type_str),
            mac_address: MacAddr6::try_from(msg.chaddr()).ok(),
            option82_circuit: None,
            option82_remote: None,
            option82_subscriber: None,
            assigned_ipv4: None,
            relay_addr,
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
    /// Unix timestamp in milliseconds
    pub timestamp_ms: u64,
    /// DHCPv6 message type
    pub message_type: &'static str,
    /// Transaction ID from the client hex string
    pub xid: String,
    /// Client's MAC address
    pub mac_address: Option<MacAddr6>,
    /// Client DUID as hex string (unique client identifier)
    pub client_id: Option<String>,
    /// Option 18: Interface-ID from relay agent
    pub relay_interface_id: Option<String>,
    /// Option 37: Remote-ID from relay agent
    pub relay_remote_id: Option<String>,
    /// Relay agent source address
    pub relay_addr: Ipv6Addr,
    /// Relay link address (network the client is on)
    pub relay_link_addr: Ipv6Addr,
    /// Relay peer address (client's link-local or address seen by relay)
    pub relay_peer_addr: Ipv6Addr,
    pub requested_ipv6_na: Option<Ipv6Addr>,
    pub requested_ipv6_pd: Option<Ipv6Net>,
    pub assigned_ipv6_na: Option<Ipv6Addr>,
    pub assigned_ipv6_pd: Option<Ipv6Net>,
    pub reservation_ipv4: Option<Ipv4Addr>,
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

    fn format_client_id(bytes: &[u8]) -> String {
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

        DhcpEventV6 {
            timestamp_ms: now(),
            message_type: Self::message_type_str(input_msg.msg_type()),
            xid: format!(
                "{:02x}{:02x}{:02x}",
                input_msg.xid()[0],
                input_msg.xid()[1],
                input_msg.xid()[2]
            ),
            mac_address: relay_msg.hw_addr(),
            client_id: input_msg.client_id().map(Self::format_client_id),
            relay_interface_id: option1837
                .as_ref()
                .and_then(|o| o.interface.as_ref().map(|s| s.to_string())),
            relay_remote_id: option1837
                .as_ref()
                .and_then(|o| o.remote.as_ref().map(|s| s.to_string())),
            relay_addr,
            relay_link_addr: relay_msg.link_addr(),
            relay_peer_addr: relay_msg.peer_addr(),
            requested_ipv6_na: input_msg.ia_na_address(),
            requested_ipv6_pd: input_msg.ia_pd_prefix(),
            assigned_ipv6_na: reservation.map(|r| r.ipv6_na),
            assigned_ipv6_pd: reservation.map(|r| r.ipv6_pd),
            reservation_ipv4: reservation.map(|r| r.ipv4),
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
            mac_address: relay_msg.hw_addr(),
            client_id: input_msg.client_id().map(Self::format_client_id),
            relay_interface_id: option1837
                .as_ref()
                .and_then(|o| o.interface.as_ref().map(|s| s.to_string())),
            relay_remote_id: option1837
                .as_ref()
                .and_then(|o| o.remote.as_ref().map(|s| s.to_string())),
            relay_addr,
            relay_link_addr: relay_msg.link_addr(),
            relay_peer_addr: relay_msg.peer_addr(),
            requested_ipv6_na: input_msg.ia_na_address(),
            requested_ipv6_pd: input_msg.ia_pd_prefix(),
            assigned_ipv6_na: None,
            assigned_ipv6_pd: None,
            reservation_ipv4: None,
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
