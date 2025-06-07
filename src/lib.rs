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
            .map(V4Key::Mac)
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
            .or(self.mac.map(V6Key::Mac))
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
    reservations: Vec<Reservation>,
    /// Lookup reservation by MAC address
    mac_reservation_index: HashMap<MacAddr6, usize>,
    /// Lookup reservation by the DUID
    duid_reservation_index: HashMap<Vec<u8>, usize>,
    /// Lookup reservation by the Option 82 value
    option82_reservation_index: HashMap<Vec<u8>, usize>,
    /// When leasing IPv4 via Option 82, record the MAC address that was used and point to the Option 82 data
    option82_mac_binding: HashMap<MacAddr6, Vec<u8>>,
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

    pub fn get_reservation_by_option82(&self, opt: &[u8]) -> Option<&Reservation> {
        self.option82_reservation_index
            .get(opt)
            .and_then(|idx| self.reservations.get(*idx))
    }

    pub fn insert_mac_option82_binding(&mut self, mac: &MacAddr6, opt: &[u8]) {
        self.option82_mac_binding.insert(*mac, opt.to_vec());
    }

    fn rebuild_indices(&mut self) {
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
            .filter_map(|(idx, r)| r.option82_circuit.as_ref().map(|opt| (opt.clone(), idx)))
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
            v4_leases: HashMap::new(),
            v6_leases: HashMap::new(),
            v4_subnets: subnets.to_vec(),
            v4_dns: v4_dns.to_vec(),
        };

        output.rebuild_indices();
        output
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
