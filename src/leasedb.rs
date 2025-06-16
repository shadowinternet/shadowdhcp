use advmac::MacAddr6;
use dashmap::DashMap;

use crate::{LeaseV4, LeaseV6, Option82, Reservation};

#[derive(Clone)]
pub struct LeaseDb {
    v4: DashMap<Reservation, LeaseV4>,
    v6: DashMap<Reservation, LeaseV6>,
    // TODO: move this somewhere else?
    mac_to_opt82: DashMap<MacAddr6, Option82>,
}

impl LeaseDb {
    pub fn new() -> Self {
        Self {
            v4: DashMap::new(),
            v6: DashMap::new(),
            mac_to_opt82: DashMap::new(),
        }
    }
    pub fn leased_new_v4(&self, reservation: &Reservation, lease: LeaseV4) {
        self.v4.insert(reservation.clone(), lease);
    }

    pub fn leased_new_v6(&self, reservation: &Reservation, lease: LeaseV6) {
        match self.v6.insert(reservation.to_owned(), lease.clone()) {
            Some(old_lease) => {
                println!(
                    "replaced existing lease {:?}, {:?} {old_lease:?} with new lease {lease:?}",
                    reservation.ipv6_na, reservation.ipv6_pd
                )
            }
            None => println!(
                "First time leased address: {:?}, {:?} to DUID {:x?} MAC {:?}",
                reservation.ipv6_na, reservation.ipv6_pd, lease.duid, lease.mac
            ),
        }
    }

    pub fn insert_mac_option82_binding(&self, mac_addr: &MacAddr6, opt: &Option82) {
        self.mac_to_opt82.insert(*mac_addr, opt.clone());
    }

    pub fn get_opt82_by_mac(&self, mac_addr: &MacAddr6) -> Option<Option82> {
        self.mac_to_opt82.get(mac_addr).map(|o| o.value().clone())
    }
}
