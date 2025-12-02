use std::{hash::Hash, sync::Arc};

use advmac::MacAddr6;
use dashmap::DashMap;

use crate::{Duid, Option1837, Option82, Reservation};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ReservationKey {
    Mac(MacAddr6),
    Duid(Duid),
    Opt82(Option82),
    Opt1837(Option1837),
}

pub struct ReservationDb {
    inner: DashMap<ReservationKey, Arc<Reservation>>,
}

impl ReservationDb {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub fn insert(&self, reservation: Reservation) {
        let stored = Arc::new(reservation);

        if let Some(mac) = stored.mac {
            self.inner.insert(ReservationKey::Mac(mac), stored.clone());
        }

        if let Some(ref duid) = stored.duid {
            self.inner
                .insert(ReservationKey::Duid(duid.clone()), stored.clone());
        }

        if let Some(ref opt82) = stored.option82 {
            self.inner
                .insert(ReservationKey::Opt82(opt82.clone()), stored.clone());
        }

        if let Some(ref opt1837) = stored.option1837 {
            self.inner
                .insert(ReservationKey::Opt1837(opt1837.clone()), stored.clone());
        }
    }

    pub fn load_reservations(&self, reservations: Vec<Reservation>) {
        for reservation in reservations.into_iter() {
            self.insert(reservation);
        }
    }

    pub fn by_mac(&self, mac: MacAddr6) -> Option<Arc<Reservation>> {
        self.inner
            .get(&ReservationKey::Mac(mac))
            .map(|r| Arc::clone(r.value()))
    }

    pub fn by_duid(&self, duid: &Duid) -> Option<Arc<Reservation>> {
        self.inner
            .get(&ReservationKey::Duid(duid.clone()))
            .map(|r| Arc::clone(r.value()))
    }

    pub fn by_opt82(&self, opt: &Option82) -> Option<Arc<Reservation>> {
        self.inner
            .get(&ReservationKey::Opt82(opt.clone()))
            .map(|r| Arc::clone(r.value()))
    }

    pub fn by_opt1837(&self, opt: &Option1837) -> Option<Arc<Reservation>> {
        self.inner
            .get(&ReservationKey::Opt1837(opt.clone()))
            .map(|r| Arc::clone(r.value()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use advmac::MacAddr6;
    use dashmap::DashMap;

    #[test]
    fn test_map_lookups() {
        let map: DashMap<ReservationKey, &'static str> = DashMap::new();

        let mac: MacAddr6 = "00:11:22:33:44:55".parse().unwrap();
        map.insert(ReservationKey::Mac(mac), "alice");

        let duid = Duid::from(vec![0xde, 0xad, 0xbe, 0xef]);
        map.insert(ReservationKey::Duid(duid.clone()), "bob");

        let opt82 = Option82 {
            circuit: Some("eth0:100".into()),
            remote: Some("00-11-22-33-44-55".into()),
            subscriber: None,
        };
        map.insert(ReservationKey::Opt82(opt82.clone()), "charlie");

        assert_eq!(
            *map.get(&ReservationKey::Mac(mac.clone())).unwrap().value(),
            "alice"
        );
        assert_eq!(
            *map.get(&ReservationKey::Duid(duid.clone()))
                .unwrap()
                .value(),
            "bob"
        );
        assert_eq!(
            *map.get(&ReservationKey::Opt82(opt82.clone()))
                .unwrap()
                .value(),
            "charlie"
        );
    }

    #[test]
    fn test_reservation_lookups() {
        let db = ReservationDb::new();

        let json_str = r#"
        [
            {
                "ipv4": "192.168.1.109",
                "ipv6_na": "2001:db8:1:2::1",
                "ipv6_pd": "2001:db8:1:3::/56",
                "mac": "00-11-22-33-44-55"
            },
            {
                "ipv4": "192.168.1.110",
                "ipv6_na": "2001:db8:1:4::1",
                "ipv6_pd": "2001:db8:1:5::/56",
                "mac": "00-11-22-33-44-57"
            },
            {
                "ipv4": "192.168.1.111",
                "ipv6_na": "2001:db8:1:6::1",
                "ipv6_pd": "2001:db8:1:7::/56",
                "option82": {"circuit": "99-11-22-33-44-55", "remote": "eth2:100"}
            },
            {
                "ipv4": "192.168.1.112",
                "ipv6_na": "2001:db8:1:8::1",
                "ipv6_pd": "2001:db8:1:9::/56",
                "duid": "00:11:22:33:44:55:66",
                "option82": {"subscriber": "subscriber:1020"}
            }
        ]
        "#;
        let reservations: Vec<Reservation> = serde_json::from_str(json_str).unwrap();
        db.load_reservations(reservations);

        assert_eq!(
            db.by_mac(MacAddr6::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
                .unwrap()
                .ipv4,
            Ipv4Addr::new(192, 168, 1, 109)
        );

        assert_eq!(
            db.by_duid(&Duid::from(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]))
                .unwrap()
                .ipv4,
            Ipv4Addr::new(192, 168, 1, 112)
        );

        let opt82 = Option82 {
            circuit: None,
            remote: None,
            subscriber: Some("subscriber:1020".into()),
        };

        assert_eq!(
            db.by_opt82(&opt82).unwrap().ipv4,
            Ipv4Addr::new(192, 168, 1, 112)
        );
    }
}
