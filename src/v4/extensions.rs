use dhcproto::v4::{self, DhcpOption};
use std::net::Ipv4Addr;

/// Helpers for interacting with dhcproto::v4::Message
pub trait ShadowMessageExtV4 {
    fn message_type(&self) -> Option<&v4::MessageType>;
    fn server_id(&self) -> Option<&Ipv4Addr>;
    fn requested_ip_addr(&self) -> Option<&Ipv4Addr>;
    fn relay_agent_information(&self) -> Option<&v4::relay::RelayAgentInformation>;
}

impl ShadowMessageExtV4 for v4::Message {
    fn message_type(&self) -> Option<&v4::MessageType> {
        self.opts().iter().find_map(|o| match o.1 {
            DhcpOption::MessageType(mt) => Some(mt),
            _ => None,
        })
    }

    fn relay_agent_information(&self) -> Option<&v4::relay::RelayAgentInformation> {
        self.opts().iter().find_map(|o| match o.1 {
            DhcpOption::RelayAgentInformation(relay) => Some(relay),
            _ => None,
        })
    }

    fn server_id(&self) -> Option<&Ipv4Addr> {
        self.opts().iter().find_map(|o| match o.1 {
            DhcpOption::ServerIdentifier(addr) => Some(addr),
            _ => None,
        })
    }

    fn requested_ip_addr(&self) -> Option<&Ipv4Addr> {
        self.opts().iter().find_map(|o| match o.1 {
            DhcpOption::RequestedIpAddress(addr) => Some(addr),
            _ => None,
        })
    }
}
