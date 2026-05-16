use dhcproto::v4::{self, relay::RelayAgentInformation, DhcpOption};
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

    fn relay_agent_information(&self) -> Option<&RelayAgentInformation> {
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

pub trait RelayAgentInformationExt {
    fn circuit_id(&self) -> Option<Vec<u8>>;
    fn remote_id(&self) -> Option<Vec<u8>>;
    fn subscriber_id(&self) -> Option<Vec<u8>>;
}

impl RelayAgentInformationExt for RelayAgentInformation {
    fn circuit_id(&self) -> Option<Vec<u8>> {
        self.get(dhcproto::v4::relay::RelayCode::AgentCircuitId)
            .and_then(|ri| match ri {
                dhcproto::v4::relay::RelayInfo::AgentCircuitId(v) if !v.is_empty() => {
                    Some(v.clone())
                }
                _ => None,
            })
    }

    fn remote_id(&self) -> Option<Vec<u8>> {
        self.get(dhcproto::v4::relay::RelayCode::AgentRemoteId)
            .and_then(|ri| match ri {
                dhcproto::v4::relay::RelayInfo::AgentRemoteId(v) if !v.is_empty() => {
                    Some(v.clone())
                }
                _ => None,
            })
    }

    fn subscriber_id(&self) -> Option<Vec<u8>> {
        self.get(dhcproto::v4::relay::RelayCode::SubscriberId)
            .and_then(|ri| match ri {
                dhcproto::v4::relay::RelayInfo::SubscriberId(v) if !v.is_empty() => Some(v.clone()),
                _ => None,
            })
    }
}
