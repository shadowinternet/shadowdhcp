use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use advmac::MacAddr6;
use dhcproto::v4::relay::RelayAgentInformation;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::extractors::Option82ExtractorFn;

pub mod extractors;

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    pub duid: Option<Vec<u8>>,
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
    Duid(Vec<u8>),
    Mac(MacAddr6),
}

pub struct V6Ip {
    pub ia_na: Ipv6Addr,
    pub ia_pd: Ipv6Net,
}

#[derive(Debug, Clone)]
pub struct V4Subnet {
    pub net: Ipv4Net,
    pub gateway: Ipv4Addr,
}

pub struct Lease<T> {
    pub first_leased: Instant,
    pub last_leased: Instant,
    pub valid: Duration,
    pub source: T,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Option82 {
    pub circuit: Option<String>,
    pub remote: Option<String>,
    pub subscriber: Option<String>,
}

pub struct Storage {
    reservations: Vec<Reservation>,
    /// Lookup reservation by MAC address
    mac_reservation_index: HashMap<MacAddr6, usize>,
    /// Lookup reservation by the DUID
    duid_reservation_index: HashMap<Vec<u8>, usize>,
    /// Lookup reservation by the Option 82 value
    option82_reservation_index: HashMap<Option82, usize>,
    /// When leasing IPv4 via Option 82, record the MAC address that was used and point to the Option 82 data
    option82_mac_binding: HashMap<MacAddr6, Option82>,
    option82_extractors: Vec<Option82ExtractorFn>,
    pub v4_leases: HashMap<Ipv4Addr, Lease<V4Key>>,
    pub v6_leases: HashMap<V6Ip, Lease<V6Key>>,
    pub v4_subnets: Vec<V4Subnet>,
    pub v4_dns: Vec<Ipv4Addr>,
}

impl Storage {
    /// Return reservation for MAC address, or try to find reservation by dynamic option82 data
    pub fn get_reservation_by_mac(&self, mac: &MacAddr6) -> Option<&Reservation> {
        self.mac_reservation_index
            .get(mac)
            .and_then(|idx| self.reservations.get(*idx))
            .or(self
                .option82_mac_binding
                .get(mac)
                .and_then(|opt| self.get_reservation_by_option82(opt)))
    }

    pub fn get_reservation_by_duid(&self, duid: &[u8]) -> Option<&Reservation> {
        self.duid_reservation_index
            .get(duid)
            .and_then(|idx| self.reservations.get(*idx))
    }

    pub fn get_reservation_by_option82(&self, opt: &Option82) -> Option<&Reservation> {
        self.option82_reservation_index
            .get(opt)
            .and_then(|idx| self.reservations.get(*idx))
    }

    /// Check for a reservation in the following order of subcodes:
    /// * Remote-ID
    /// * Subscriber-ID
    /// * Circuit-ID + Remote-ID
    /// * Circuit-ID
    pub fn get_reservation_by_relay_information(
        &self,
        relay: &RelayAgentInformation,
    ) -> Option<&Reservation> {
        let circuit = relay.circuit_id().and_then(|v| String::from_utf8(v).ok());
        let remote = relay.remote_id().and_then(|v| String::from_utf8(v).ok());
        let subscriber = relay
            .subscriber_id()
            .and_then(|v| String::from_utf8(v).ok());

        self.get_reservation_by_option82(&Option82 {
            circuit: None,
            remote: remote.clone(),
            subscriber: None,
        })
        .or(self.get_reservation_by_option82(&Option82 {
            circuit: None,
            remote: None,
            subscriber,
        }))
        .or(self.get_reservation_by_option82(&Option82 {
            circuit: circuit.clone(),
            remote,
            subscriber: None,
        }))
        .or(self.get_reservation_by_option82(&Option82 {
            circuit,
            remote: None,
            subscriber: None,
        }))
        .or_else(|| {
            let option = Option82 {
                circuit: relay.circuit_id().and_then(|v| String::from_utf8(v).ok()),
                remote: relay.remote_id().and_then(|v| String::from_utf8(v).ok()),
                subscriber: relay
                    .subscriber_id()
                    .and_then(|v| String::from_utf8(v).ok()),
            };
            self.option82_extractors.iter().find_map(|extractor| {
                extractor(&option)
                    .and_then(|extracted_opt| self.get_reservation_by_option82(&extracted_opt))
            })
        })
    }

    pub fn insert_mac_option82_binding(&mut self, mac: &MacAddr6, opt: &Option82) {
        self.option82_mac_binding.insert(*mac, opt.clone());
    }

    fn rebuild_indices(&mut self) {
        // TODO: check for duplicate reservations
        self.mac_reservation_index = self
            .reservations
            .iter()
            .enumerate()
            .filter_map(|(idx, r)| r.mac.map(|mac| (mac, idx)))
            .collect();

        self.duid_reservation_index = self
            .reservations
            .iter()
            .enumerate()
            .filter_map(|(idx, r)| r.duid.as_ref().map(|duid| (duid.clone(), idx)))
            .collect();

        // TODO: update option82 data type?
        self.option82_reservation_index = self
            .reservations
            .iter()
            .enumerate()
            .filter_map(|(idx, r)| r.option82.as_ref().map(|opt| (opt.clone(), idx)))
            .collect();

        // only retain current option82
        self.option82_mac_binding
            .retain(|_k, v| self.option82_reservation_index.contains_key(v));
    }

    pub fn new(reservations: &[Reservation], subnets: &[V4Subnet], v4_dns: &[Ipv4Addr]) -> Self {
        let mut output = Storage {
            reservations: reservations.to_vec(),
            mac_reservation_index: HashMap::new(),
            duid_reservation_index: HashMap::new(),
            option82_reservation_index: HashMap::new(),
            option82_mac_binding: HashMap::new(),
            option82_extractors: extractors::get_all_extractors().into_values().collect(),
            v4_leases: HashMap::new(),
            v6_leases: HashMap::new(),
            v4_subnets: subnets.to_vec(),
            v4_dns: v4_dns.to_vec(),
        };

        output.rebuild_indices();
        output
    }
}

trait RelayAgentInformationExt {
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
    fn load_reservations() {
        let json_str = r#"
        [
            {
                "ipv4": "192.168.1.109",
                "ipv6_na": "2605:cb40:1:2::1",
                "ipv6_pd": "2605:cb40:1:3::/56",
                "mac": "00-11-22-33-44-55"
            },
            {
                "ipv4": "192.168.1.110",
                "ipv6_na": "2605:cb40:1:4::1",
                "ipv6_pd": "2605:cb40:1:5::/56",
                "mac": "00-11-22-33-44-57"
            },
            {
                "ipv4": "192.168.1.111",
                "ipv6_na": "2605:cb40:1:6::1",
                "ipv6_pd": "2605:cb40:1:7::/56",
                "option82": {"circuit": "99-11-22-33-44-55", "remote": "eth2:100"}
            },
            {
                "ipv4": "192.168.1.112",
                "ipv6_na": "2605:cb40:1:8::1",
                "ipv6_pd": "2605:cb40:1:9::/56",
                "option82": {"subscriber": "subscriber:1020"}
            }
        ]
        "#;
        let reservations: Vec<Reservation> = serde_json::from_str(json_str).unwrap();
        let subnets = [V4Subnet {
            net: "192.168.0.0/24".parse().unwrap(),
            gateway: "192.168.0.1".parse().unwrap(),
        }];
        let v4_dns = [Ipv4Addr::from([8, 8, 8, 8]), Ipv4Addr::from([8, 8, 4, 4])];

        let storage = Storage::new(&reservations, &subnets, &v4_dns);
        assert_eq!(
            Ipv4Addr::from([192, 168, 1, 109]),
            storage
                .get_reservation_by_mac(&MacAddr6::parse_str("00:11:22:33:44:55").unwrap())
                .unwrap()
                .ipv4
        );
        assert_eq!(
            Ipv4Addr::from([192, 168, 1, 110]),
            storage
                .get_reservation_by_mac(&MacAddr6::parse_str("00:11:22:33:44:57").unwrap())
                .unwrap()
                .ipv4
        );
    }
}
