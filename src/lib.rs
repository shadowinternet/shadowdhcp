use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use advmac::MacAddr6;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

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
    pub option82_circuit: Option<Vec<u8>>,
    // option82 info used if mac is not specified
    pub option82_remote: Option<Vec<u8>>,
}

impl Reservation {
    /// Get the V4 key used for the reservation with the following order precedence
    /// MAC Address, Option82
    pub fn v4_key(&self) -> Option<V4Key> {
        self.mac
            .map(|m| V4Key::Mac(m))
            .or(self
                .option82_circuit
                .as_ref()
                .map(|o| V4Key::Option82(o.clone())))
            .or(self
                .option82_remote
                .as_ref()
                .map(|o| V4Key::Option82(o.clone())))
    }

    /// Get the V6 key used for the reservation with the following order precedence
    /// DUID, MAC Address.
    /// In the case of Option82, the V6 Reservation will be dynamically generated
    pub fn v6_key(&self) -> Option<V6Key> {
        self.duid
            .as_ref()
            .map(|d| V6Key::Duid(d.clone()))
            .or(self.mac.map(|m| V6Key::Mac(m)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum V4Key {
    Mac(MacAddr6),
    Option82(Vec<u8>),
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

pub struct Storage {
    pub v4_reservations: HashMap<V4Key, Ipv4Addr>,
    pub v6_reservations: HashMap<V6Key, V6Ip>,
    pub v4_leases: HashMap<Ipv4Addr, Lease<V4Key>>,
    pub v6_leases: HashMap<V6Ip, Lease<V6Key>>,
    pub v4_subnets: Vec<V4Subnet>,
    pub v4_dns: Vec<Ipv4Addr>,
}

impl Storage {
    pub fn new(reservations: &[Reservation], subnets: &[V4Subnet], v4_dns: &[Ipv4Addr]) -> Self {
        let mut v4 = HashMap::new();
        let mut v6 = HashMap::new();

        for r in reservations {
            match r.v4_key() {
                Some(key) => v4.insert(key, r.ipv4),
                None => {
                    eprintln!("No IPv4 key for reservation IPv4: {}", r.ipv4);
                    continue;
                }
            };

            // if we have a v4 key, we are guaranteed to have a v6 key either
            // via MAC address, or dynamically added by option 82
            if let Some(key) = r.v6_key() {
                v6.insert(
                    key,
                    V6Ip {
                        ia_na: r.ipv6_na,
                        ia_pd: r.ipv6_pd,
                    },
                );
            }
        }

        Self {
            v4_reservations: v4,
            v6_reservations: v6,
            v4_leases: HashMap::new(),
            v6_leases: HashMap::new(),
            v4_subnets: subnets.into(),
            v4_dns: v4_dns.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_reservations() {
        let json_str = include_str!("../reservations.json");
        let reservations: Vec<Reservation> = serde_json::from_str(json_str).unwrap();
        let subnets = [V4Subnet {
            net: "192.168.0.0/24".parse().unwrap(),
            gateway: "192.168.0.1".parse().unwrap(),
        }];
        let v4_dns = [Ipv4Addr::from([8, 8, 8, 8]), Ipv4Addr::from([8, 8, 4, 4])];

        let storage = Storage::new(&reservations, &subnets, &v4_dns);
        println!(
            "num ipv4: {}, num ipv6: {}",
            storage.v4_reservations.len(),
            storage.v6_reservations.len()
        );
    }
}
