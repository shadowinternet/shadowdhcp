use core::fmt;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use advmac::MacAddr6;
use compact_str::{format_compact, CompactString, CompactStringExt};
use dhcproto::v4::relay::RelayAgentInformation;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{de::Visitor, Deserialize, Serialize};

use crate::extractors::Option82ExtractorFn;

pub mod extractors;
pub mod leasedb;
pub mod logging;
pub mod reservationdb;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub struct Reservation {
    // customer WAN v4 address
    pub ipv4: Ipv4Addr,
    // customer WAN v6 address /64
    pub ipv6_na: Ipv6Addr,
    // customer LAN prefix delegation /56
    pub ipv6_pd: Ipv6Net,
    // customer router WAN mac address. Overrides option82 settings
    pub mac: Option<MacAddr6>,
    // customer router duid. Overrides option82 settings, and mac setting for ipv6
    pub duid: Option<Duid>,
    // option82 info used if mac is not specified
    pub option82: Option<Option82>,
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

    /// Get the V6 key used for the reservation with the following order precedence
    /// DUID, MAC Address.
    /// In the case of Option82, the V6 Reservation will be dynamically generated
    pub fn v6_key(&self) -> Option<V6Key> {
        self.duid
            .as_ref()
            .map(|d| V6Key::Duid(d.clone()))
            .or(self.mac.map(V6Key::Mac))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum V4Key {
    Mac(MacAddr6),
    Option82(Option82),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum V6Key {
    Duid(Duid),
    Mac(MacAddr6),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct V6Ip {
    pub ia_na: Ipv6Addr,
    pub ia_pd: Ipv6Net,
}

#[derive(Debug, Clone)]
pub struct V4Subnet {
    pub net: Ipv4Net,
    pub gateway: Ipv4Addr,
}

pub struct Config {
    pub dns_v4: Vec<Ipv4Addr>,
    pub subnets_v4: Vec<V4Subnet>,
    pub option82_extractors: Vec<Option82ExtractorFn>,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Duid {
    pub bytes: Vec<u8>,
}

impl Duid {
    pub fn to_colon_string(&self) -> String {
        self.bytes
            .iter()
            .map(|byte| format_compact!("{:x}", byte))
            .join_compact(":")
            .to_string()
    }
}

impl fmt::Display for Duid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.bytes)
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
pub struct DuidParseError {}
impl std::error::Error for DuidParseError {}
impl std::fmt::Display for DuidParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid DUID format")
    }
}

// TODO: support UUID
// TODO: support raw bytes, or other data
impl TryFrom<&str> for Duid {
    type Error = DuidParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.trim().as_bytes().get(2) {
            Some(&b':') => value
                .trim()
                .split(':')
                .map(|hex| u8::from_str_radix(hex, 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| DuidParseError {})
                .map(Duid::from),
            Some(&b'-') => value
                .trim()
                .split('-')
                .map(|hex| u8::from_str_radix(hex, 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| DuidParseError {})
                .map(Duid::from),
            _ => Err(DuidParseError {}),
        }
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

        #[derive(Deserialize)]
        struct DuidJson {
            duid: Duid,
        }
        let json = r#"{"duid": "29:30:31:32:33:34:35:36:37:38:39:40:41:42:43:44"}"#;
        let parsed_json: DuidJson = serde_json::from_str(json).unwrap();

        assert_eq!(parsed_json.duid, duid);
    }
}
