#![allow(unused)]
use dhcproto::v6;
use serde::Serialize;
use shadow_dhcpv6::Reservation;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
pub enum DhcpEvent {
    V6(DhcpEventV6),
    V4,
}

#[derive(Serialize)]
pub struct DhcpEventV6 {
    pub timestamp_ms: u64,
    pub message_type: &'static str,
    //pub xid: [u8; 3],
    //pub mac_address: Option<String>,
    //pub client_id: Option<String>,
    //pub opt1837_interface: Option<String>,
    //pub opt1837_remote: Option<String>,
    //pub requested_ipv6_na: Option<Ipv6Addr>,
    //pub assigned_ipv6_na: Option<Ipv6Addr>,
    //pub requested_ipv6_pd: Option<Ipv6Net>,
    //pub assigned_ipv6_pd: Option<Ipv6Net>,
    //pub relay_link_addr: Option<Ipv6Addr>,
    //pub relay_peer_addr: Option<Ipv6Addr>,
    //pub success: bool,
    //pub failure_reason: Option<&'static str>,
}

impl DhcpEventV6 {
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    pub fn success(
        input_msg: &v6::Message,
        relay_msg: &v6::RelayMessage,
        output_msg: &v6::Message,
        reservation: Option<&Reservation>,
    ) -> Self {
        DhcpEventV6 {
            timestamp_ms: 100,
            message_type: "request",
        }
    }

    pub fn failed(
        input_msg: &v6::Message,
        relay_msg: &v6::RelayMessage,
        reason: &'static str,
    ) -> DhcpEventV6 {
        DhcpEventV6 {
            timestamp_ms: 100,
            message_type: "request",
        }
    }
}
