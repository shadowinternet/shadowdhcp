use core::fmt;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use advmac::MacAddr6;
use compact_str::CompactString;
use dhcproto::v4::relay::RelayAgentInformation;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{de::Visitor, Deserialize, Serialize};

pub mod logging;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct Reservation {
    // customer WAN v4 address
    pub ipv4: Ipv4Addr,
    // customer WAN v6 address /64
    pub ipv6_na: Ipv6Addr,
    // customer LAN prefix delegation /56
    pub ipv6_pd: Ipv6Net,
    // customer router WAN mac address. Overrides option82 settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr6>,
    // customer router duid. Overrides option82 settings, and mac setting for ipv6
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duid: Option<Duid>,
    // option82 info used if mac is not specified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option82: Option<Option82>,
    // option1837 contains dhcpv6 option 18 and option 37, the v6 equivalent to option 82
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option1837: Option<Option1837>,
}

impl Reservation {
    /// Get the V4 key used for the reservation with the following order precedence
    /// MAC Address, Option82
    pub fn v4_key(&self) -> Option<V4Key> {
        self.mac.map(V4Key::Mac).or(self
            .option82
            .as_ref()
            .map(|opt| V4Key::Option82(opt.clone())))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum V4Key {
    Mac(MacAddr6),
    Option82(Option82),
}

#[derive(Debug, Clone, Deserialize)]
pub struct V4Subnet {
    pub net: Ipv4Net,
    pub gateway: Ipv4Addr,
    /// Optional override for the subnet mask sent in DHCP replies
    pub reply_prefix_len: Option<u8>,
}

impl V4Subnet {
    /// Returns the subnet mask to use in DHCP replies.
    /// Uses `reply_prefix_len` if set, otherwise uses the prefix from `net`.
    pub fn reply_netmask(&self) -> Ipv4Addr {
        let prefix_len = self.reply_prefix_len.unwrap_or(self.net.prefix_len());
        // Convert prefix length to netmask by setting the high bits
        if prefix_len == 0 {
            Ipv4Addr::new(0, 0, 0, 0)
        } else if prefix_len >= 32 {
            Ipv4Addr::new(255, 255, 255, 255)
        } else {
            let mask = !((1u32 << (32 - prefix_len)) - 1);
            Ipv4Addr::from(mask)
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(len) = self.reply_prefix_len {
            if len > 32 {
                return Err("reply_prefix_len must be between 0 and 32");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LeaseV4 {
    pub first_leased: Instant,
    pub last_leased: Instant,
    pub valid: Duration,
    pub mac: MacAddr6,
    pub option82: Option<Option82>,
}

#[derive(Debug, Clone)]
pub struct LeaseV6 {
    pub first_leased: Instant,
    pub last_leased: Instant,
    pub valid: Duration,
    pub duid: Duid,
    pub mac: Option<MacAddr6>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Option82 {
    pub circuit: Option<CompactString>,
    pub remote: Option<CompactString>,
    pub subscriber: Option<CompactString>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Option1837 {
    /// Option 18 Interface-ID field
    pub interface: Option<CompactString>,
    /// Option 37 remote-id field
    pub remote: Option<CompactString>,
    /// Option 37 enterprise-number field
    pub enterprise_number: Option<u32>,
}

/// Maximum DUID length per RFC 8415 Section 11.1
pub const MAX_DUID_LEN: usize = 130;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Duid {
    pub bytes: Vec<u8>,
}

impl Duid {
    /// Create a new DUID with length validation.
    /// Returns None if the DUID exceeds MAX_DUID_LEN (130 bytes).
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() > MAX_DUID_LEN {
            return None;
        }
        Some(Duid { bytes })
    }
}

impl fmt::Display for Duid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, b) in self.bytes.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl Serialize for Duid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Duid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DuidVisitor;
        impl<'de> Visitor<'de> for DuidVisitor {
            type Value = Duid;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(r#"colon or dash separated hex "00:11:22" or "00-11-22""#)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Duid::try_from(v).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(DuidVisitor)
    }
}

impl From<Vec<u8>> for Duid {
    fn from(value: Vec<u8>) -> Self {
        Duid { bytes: value }
    }
}

impl From<Duid> for dhcproto::v6::duid::Duid {
    fn from(value: Duid) -> Self {
        Self::from(value.bytes)
    }
}

// TODO: modify dhcproto to have `impl From<Duid> for Vec<u8>`
// TODO: modify dhcproto to parse strings into Duid
impl From<dhcproto::v6::duid::Duid> for Duid {
    fn from(value: dhcproto::v6::duid::Duid) -> Self {
        Self::from(value.as_ref())
    }
}

impl From<&[u8]> for Duid {
    fn from(value: &[u8]) -> Self {
        Duid {
            bytes: value.to_vec(),
        }
    }
}

#[derive(Debug)]
pub struct DuidParseError {
    pub message: &'static str,
}
impl std::error::Error for DuidParseError {}
impl std::fmt::Display for DuidParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl Default for DuidParseError {
    fn default() -> Self {
        Self {
            message: "Invalid DUID format",
        }
    }
}

// TODO: support UUID
// TODO: support raw bytes, or other data
impl TryFrom<&str> for Duid {
    type Error = DuidParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = match value.trim().as_bytes().get(2) {
            Some(&b':') => value
                .trim()
                .split(':')
                .map(|hex| u8::from_str_radix(hex, 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| DuidParseError::default())?,
            Some(&b'-') => value
                .trim()
                .split('-')
                .map(|hex| u8::from_str_radix(hex, 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| DuidParseError::default())?,
            _ => return Err(DuidParseError::default()),
        };
        if bytes.len() > MAX_DUID_LEN {
            return Err(DuidParseError {
                message: "DUID exceeds maximum length of 130 bytes",
            });
        }
        Ok(Duid { bytes })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duid() {
        let duid_str_colon = "29:30:31:32:33:34:35:36:37:38:39:40:41:42:43:44";
        let duid_str_dash = "29-30-31-32-33-34-35-36-37-38-39-40-41-42-43-44";
        let duid = Duid::from(vec![
            0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42,
            0x43, 0x44,
        ]);

        let duid_parsed_colon = Duid::try_from(duid_str_colon).unwrap();
        assert_eq!(duid_parsed_colon, duid);
        let duid_parsed_dash = Duid::try_from(duid_str_dash).unwrap();
        assert_eq!(duid_parsed_dash, duid);
        assert_eq!(duid_parsed_colon.to_string(), duid_str_colon);

        #[derive(Deserialize)]
        struct DuidJson {
            duid: Duid,
        }
        let json = r#"{"duid": "29:30:31:32:33:34:35:36:37:38:39:40:41:42:43:44"}"#;
        let parsed_json: DuidJson = serde_json::from_str(json).unwrap();

        assert_eq!(parsed_json.duid, duid);
    }

    #[test]
    fn v4subnet_reply_netmask_uses_net_prefix_when_override_not_set() {
        let subnet = V4Subnet {
            net: "192.168.1.0/24".parse().unwrap(),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            reply_prefix_len: None,
        };
        assert_eq!(subnet.reply_netmask(), Ipv4Addr::new(255, 255, 255, 0));

        let subnet_16 = V4Subnet {
            net: "10.0.0.0/16".parse().unwrap(),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            reply_prefix_len: None,
        };
        assert_eq!(subnet_16.reply_netmask(), Ipv4Addr::new(255, 255, 0, 0));
    }

    #[test]
    fn v4subnet_reply_netmask_uses_override_when_set() {
        let subnet = V4Subnet {
            net: "192.168.1.0/24".parse().unwrap(),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            reply_prefix_len: Some(32),
        };
        assert_eq!(subnet.reply_netmask(), Ipv4Addr::new(255, 255, 255, 255));

        let subnet_30 = V4Subnet {
            net: "192.168.1.0/24".parse().unwrap(),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            reply_prefix_len: Some(30),
        };
        assert_eq!(subnet_30.reply_netmask(), Ipv4Addr::new(255, 255, 255, 252));
    }

    #[test]
    fn v4subnet_validate_accepts_valid_prefix_lengths() {
        for prefix in 0..=32 {
            let subnet = V4Subnet {
                net: "192.168.1.0/24".parse().unwrap(),
                gateway: Ipv4Addr::new(192, 168, 1, 1),
                reply_prefix_len: Some(prefix),
            };
            assert!(
                subnet.validate().is_ok(),
                "prefix {} should be valid",
                prefix
            );
        }
    }

    #[test]
    fn v4subnet_validate_rejects_invalid_prefix_lengths() {
        for prefix in [33, 64, 128, 255] {
            let subnet = V4Subnet {
                net: "192.168.1.0/24".parse().unwrap(),
                gateway: Ipv4Addr::new(192, 168, 1, 1),
                reply_prefix_len: Some(prefix),
            };
            assert!(
                subnet.validate().is_err(),
                "prefix {} should be invalid",
                prefix
            );
        }
    }
}
