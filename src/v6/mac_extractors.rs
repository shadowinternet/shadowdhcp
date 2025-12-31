//! MAC address extraction methods for DHCPv6 relay messages.
//!
//! Provides configurable extraction of client MAC addresses from relay messages
//! using multiple sources with varying reliability levels.

use advmac::MacAddr6;
use dhcproto::v6::{DhcpOption, Message, RelayMessage};
use serde::Deserialize;
use tracing::debug;

/// MAC address extraction method.
///
/// Each variant represents a different source from which a client's MAC address
/// can be extracted. Methods are listed roughly in order of reliability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacExtractor {
    /// Extract from RFC 6939 Client Link-Layer Address Option (Option 79).
    /// Most reliable - explicitly added by first-hop relay agent.
    ClientLinklayerAddress,

    /// Extract from relay message peer_addr using EUI-64 reversal.
    /// Only works if client uses EUI-64 derived link-local address.
    PeerAddrEui64,

    /// Extract from client DUID (DUID-LLT type 1 or DUID-LL type 3).
    /// Least reliable - RFC 8415 warns MAC may have changed since DUID creation.
    Duid,
}

impl MacExtractor {
    /// Attempt to extract a MAC address using this method.
    pub fn extract(&self, relay_msg: &RelayMessage, msg: &Message) -> Option<MacAddr6> {
        match self {
            Self::ClientLinklayerAddress => extract_client_linklayer_address(relay_msg),
            Self::PeerAddrEui64 => extract_peer_addr_eui64(relay_msg),
            Self::Duid => extract_duid(msg),
        }
    }

    /// Get the name of this extraction method for logging/analytics.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ClientLinklayerAddress => "client_linklayer_address",
            Self::PeerAddrEui64 => "peer_addr_eui64",
            Self::Duid => "duid",
        }
    }
}

/// Extract MAC from RFC 6939 Client Link-Layer Address Option.
fn extract_client_linklayer_address(relay_msg: &RelayMessage) -> Option<MacAddr6> {
    relay_msg.opts().iter().find_map(|opt| match opt {
        DhcpOption::ClientLinklayerAddress(ll) if ll.address.len() == 6 => {
            let mut bytes: [u8; 6] = [0; 6];
            bytes.copy_from_slice(&ll.address[0..6]);
            Some(MacAddr6::new(bytes))
        }
        DhcpOption::ClientLinklayerAddress(ll) => {
            debug!("ClientLinklayerAddress wasn't 6 bytes: {:?}", ll);
            None
        }
        _ => None,
    })
}

/// Extract MAC from relay peer_addr by reversing EUI-64 encoding.
///
/// EUI-64 link-local addresses have the format:
/// fe80::XXYY:ZZff:feAA:BBCC where the MAC is XX:YY:ZZ:AA:BB:CC
/// with the 7th bit of XX flipped (universal/local bit).
fn extract_peer_addr_eui64(relay_msg: &RelayMessage) -> Option<MacAddr6> {
    let peer_addr = relay_msg.peer_addr();
    let octets = peer_addr.octets();

    // Check if link-local (fe80::/10)
    if octets[0] != 0xfe || (octets[1] & 0xc0) != 0x80 {
        return None;
    }

    // Check for EUI-64 marker: bytes 11-12 should be ff:fe
    if octets[11] != 0xff || octets[12] != 0xfe {
        return None;
    }

    // Extract MAC: bytes 8-10 and 13-15, flip 7th bit of first byte
    let mac = [
        octets[8] ^ 0x02, // Flip universal/local bit
        octets[9],
        octets[10],
        octets[13],
        octets[14],
        octets[15],
    ];

    Some(MacAddr6::new(mac))
}

/// DUID type codes from RFC 8415.
const DUID_LLT: u16 = 1; // Link-layer address plus time
const DUID_LL: u16 = 3; // Link-layer address

/// Hardware type for Ethernet from IANA.
const HTYPE_ETHERNET: u16 = 1;

/// Extract MAC from client DUID if it's DUID-LLT or DUID-LL type.
///
/// DUID-LLT format: type(2) + htype(2) + time(4) + link-layer(variable)
/// DUID-LL format:  type(2) + htype(2) + link-layer(variable)
fn extract_duid(msg: &Message) -> Option<MacAddr6> {
    let client_id = msg.opts().iter().find_map(|opt| match opt {
        DhcpOption::ClientId(id) => Some(id.as_slice()),
        _ => None,
    })?;

    if client_id.len() < 4 {
        return None;
    }

    let duid_type = u16::from_be_bytes([client_id[0], client_id[1]]);
    let htype = u16::from_be_bytes([client_id[2], client_id[3]]);

    // Only handle Ethernet hardware type
    if htype != HTYPE_ETHERNET {
        debug!(
            "DUID hardware type {} is not Ethernet, skipping MAC extraction",
            htype
        );
        return None;
    }

    match duid_type {
        DUID_LLT => {
            // DUID-LLT: type(2) + htype(2) + time(4) + MAC(6) = 14 bytes minimum
            if client_id.len() < 14 {
                return None;
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&client_id[8..14]);
            Some(MacAddr6::new(mac))
        }
        DUID_LL => {
            // DUID-LL: type(2) + htype(2) + MAC(6) = 10 bytes minimum
            if client_id.len() < 10 {
                return None;
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&client_id[4..10]);
            Some(MacAddr6::new(mac))
        }
        _ => {
            debug!(
                "DUID type {} does not contain link-layer address",
                duid_type
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v6::{DhcpOptions, MessageType};
    use std::net::Ipv6Addr;

    fn create_relay_msg(peer_addr: Ipv6Addr) -> RelayMessage {
        RelayMessage {
            msg_type: MessageType::RelayForw,
            hop_count: 0,
            link_addr: Ipv6Addr::UNSPECIFIED,
            peer_addr,
            opts: DhcpOptions::new(),
        }
    }

    #[test]
    fn test_peer_addr_eui64_extraction() {
        // MAC 00:1a:2b:3c:4d:5e becomes EUI-64 021a:2bff:fe3c:4d5e
        // (first byte 00 -> 02 due to universal/local bit flip)
        let eui64_addr: Ipv6Addr = "fe80::21a:2bff:fe3c:4d5e".parse().unwrap();
        let relay_msg = create_relay_msg(eui64_addr);

        let mac = extract_peer_addr_eui64(&relay_msg);
        assert_eq!(
            mac,
            Some(MacAddr6::new([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]))
        );
    }

    #[test]
    fn test_peer_addr_non_eui64_returns_none() {
        // Non-EUI-64 link-local (no ff:fe marker)
        let non_eui64_addr: Ipv6Addr = "fe80::1234:5678:9abc:def0".parse().unwrap();
        let relay_msg = create_relay_msg(non_eui64_addr);

        assert_eq!(extract_peer_addr_eui64(&relay_msg), None);
    }

    #[test]
    fn test_peer_addr_non_link_local_returns_none() {
        // Global address with EUI-64 pattern still should not match
        let global_addr: Ipv6Addr = "2001:db8::21a:2bff:fe3c:4d5e".parse().unwrap();
        let relay_msg = create_relay_msg(global_addr);

        assert_eq!(extract_peer_addr_eui64(&relay_msg), None);
    }

    #[test]
    fn test_duid_llt_extraction() {
        // DUID-LLT: type=1, htype=1 (Ethernet), time=0x12345678, MAC=00:11:22:33:44:55
        let duid_llt = vec![
            0x00, 0x01, // type = DUID-LLT
            0x00, 0x01, // htype = Ethernet
            0x12, 0x34, 0x56, 0x78, // time
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC
        ];

        let mut msg = Message::new(dhcproto::v6::MessageType::Solicit);
        msg.opts_mut().insert(DhcpOption::ClientId(duid_llt));

        let mac = extract_duid(&msg);
        assert_eq!(
            mac,
            Some(MacAddr6::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
    }

    #[test]
    fn test_duid_ll_extraction() {
        // DUID-LL: type=3, htype=1 (Ethernet), MAC=aa:bb:cc:dd:ee:ff
        let duid_ll = vec![
            0x00, 0x03, // type = DUID-LL
            0x00, 0x01, // htype = Ethernet
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // MAC
        ];

        let mut msg = Message::new(dhcproto::v6::MessageType::Solicit);
        msg.opts_mut().insert(DhcpOption::ClientId(duid_ll));

        let mac = extract_duid(&msg);
        assert_eq!(
            mac,
            Some(MacAddr6::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
        );
    }

    #[test]
    fn test_duid_en_returns_none() {
        // DUID-EN (type 2) does not contain a link-layer address
        let duid_en = vec![
            0x00, 0x02, // type = DUID-EN
            0x00, 0x00, 0x00, 0x09, // enterprise number
            0x01, 0x02, 0x03, 0x04, // identifier
        ];

        let mut msg = Message::new(dhcproto::v6::MessageType::Solicit);
        msg.opts_mut().insert(DhcpOption::ClientId(duid_en));

        assert_eq!(extract_duid(&msg), None);
    }

    #[test]
    fn test_duid_non_ethernet_returns_none() {
        // DUID-LL with non-Ethernet hardware type (e.g., Infiniband = 32)
        let duid_ll_ib = vec![
            0x00, 0x03, // type = DUID-LL
            0x00, 0x20, // htype = Infiniband (32)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // 8-byte IB address
        ];

        let mut msg = Message::new(dhcproto::v6::MessageType::Solicit);
        msg.opts_mut().insert(DhcpOption::ClientId(duid_ll_ib));

        assert_eq!(extract_duid(&msg), None);
    }

    #[test]
    fn test_extractor_names() {
        assert_eq!(
            MacExtractor::ClientLinklayerAddress.name(),
            "client_linklayer_address"
        );
        assert_eq!(MacExtractor::PeerAddrEui64.name(), "peer_addr_eui64");
        assert_eq!(MacExtractor::Duid.name(), "duid");
    }
}
