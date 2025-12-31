use std::net::Ipv6Addr;

use advmac::MacAddr6;
use compact_str::CompactString;
use dhcproto::v6::{DhcpOption, Message, RelayMessage, IANA, IAPD};
use ipnet::Ipv6Net;
use shadow_dhcpv6::Option1837;
use tracing::debug;

/// Helpers for interacting with dhcproto::v6::Message
pub trait ShadowMessageExtV6 {
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

/// Helpers for interacting with dhcproto::v6::RelayMessage
pub trait ShadowRelayMessageExtV6 {
    fn option1837(&self) -> Option<Option1837>;
    fn hw_addr(&self) -> Option<MacAddr6>;
}

impl ShadowMessageExtV6 for Message {
    /// Get the bytes representing the DUID
    fn client_id(&self) -> Option<&[u8]> {
        self.opts().iter().find_map(|opt| match opt {
            DhcpOption::ClientId(id) => Some(id.as_slice()),
            _ => None,
        })
    }

    fn server_id(&self) -> Option<&[u8]> {
        self.opts().iter().find_map(|opt| match opt {
            DhcpOption::ServerId(id) => Some(id.as_slice()),
            _ => None,
        })
    }

    fn rapid_commit(&self) -> bool {
        self.opts()
            .iter()
            .any(|opt| matches!(opt, DhcpOption::RapidCommit))
    }

    fn ia_na(&self) -> Option<&IANA> {
        self.opts().iter().find_map(|opt| match opt {
            DhcpOption::IANA(iana) => Some(iana),
            _ => None,
        })
    }

    fn ia_na_address(&self) -> Option<Ipv6Addr> {
        self.ia_na().and_then(|na| {
            na.opts.iter().find_map(|opt| match opt {
                DhcpOption::IAAddr(ia) => Some(ia.addr),
                _ => None,
            })
        })
    }

    fn ia_pd(&self) -> Option<&IAPD> {
        self.opts().iter().find_map(|opt| match opt {
            DhcpOption::IAPD(iapd) => Some(iapd),
            _ => None,
        })
    }

    fn ia_pd_prefix(&self) -> Option<Ipv6Net> {
        self.ia_pd().and_then(|pd| {
            pd.opts.iter().find_map(|opt| match opt {
                DhcpOption::IAPrefix(ia) => Ipv6Net::new(ia.prefix_ip, ia.prefix_len).ok(),
                _ => None,
            })
        })
    }
}

impl ShadowRelayMessageExtV6 for RelayMessage {
    fn option1837(&self) -> Option<Option1837> {
        let mut interface = None;
        let mut remote = None;
        let mut enterprise_number = None;

        for opt in self.opts().iter() {
            match opt {
                DhcpOption::InterfaceId(id) => {
                    interface = CompactString::from_utf8(id).ok();
                }
                DhcpOption::RemoteId(remote_id) => {
                    if let Ok(id) = CompactString::from_utf8(&remote_id.id) {
                        remote = Some(id);
                        enterprise_number = Some(remote_id.enterprise_number);
                    }
                }
                _ => {}
            }
        }

        if interface.is_some() || remote.is_some() {
            Some(Option1837 {
                interface,
                remote,
                enterprise_number,
            })
        } else {
            None
        }
    }

    /// Try to extract a link layer address from the relay message using the
    /// DHCPv6 Client Link-Layer Address option (RFC 6939).
    ///
    /// This is a convenience method for logging/debugging. For reservation matching,
    /// use the configurable `MacExtractor` system which supports multiple extraction
    /// methods (ClientLinklayerAddress, peer_addr EUI-64, DUID).
    ///
    /// See: <https://datatracker.ietf.org/doc/html/rfc6939#section-4>
    fn hw_addr(&self) -> Option<MacAddr6> {
        self.opts().iter().find_map(|opt| match opt {
            DhcpOption::ClientLinklayerAddress(ll) if ll.address.len() == 6 => {
                let mut bytes: [u8; 6] = [0; 6];
                bytes.copy_from_slice(&ll.address[0..6]);
                Some(MacAddr6::new(bytes))
            }
            DhcpOption::ClientLinklayerAddress(ll) => {
                debug!("Relay ClientLinkLayerAddress wasn't 6 bytes: {:?}", ll);
                None
            }
            _ => None,
        })
    }
}
