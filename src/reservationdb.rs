use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    sync::Arc,
};

use advmac::MacAddr6;
use dashmap::DashMap;

use crate::{Duid, Option82, Reservation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservationKey {
    Mac(MacAddr6),
    Duid(Duid),
    Opt82(Option82),
}

/* ---------- Hash/Eq for the owned key ----------------------------------- */
/* IMPORTANT: for each variant we hash ONLY the payload,                     */
/*           so that the hash equals the hash of the borrowed key.           */
impl Hash for ReservationKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            ReservationKey::Mac(m) => m.hash(state),
            ReservationKey::Duid(d) => d.hash(state),
            ReservationKey::Opt82(o) => o.hash(state),
        }
    }
}

// Impl Borrow for ReservationKey for DashMap lookups

impl Borrow<MacAddr6> for ReservationKey {
    fn borrow(&self) -> &MacAddr6 {
        match self {
            ReservationKey::Mac(ref m) => m,
            _ => panic!("called borrow::<MacAddr6> on non-Mac key"),
        }
    }
}

impl Borrow<Duid> for ReservationKey {
    fn borrow(&self) -> &Duid {
        match self {
            ReservationKey::Duid(ref d) => d,
            _ => panic!("called borrow::<Duid> on non-Duid key"),
        }
    }
}

impl Borrow<Option82> for ReservationKey {
    fn borrow(&self) -> &Option82 {
        match self {
            ReservationKey::Opt82(ref o) => o,
            _ => panic!("called borrow::<Option82> on non-Opt82 key"),
        }
    }
}

/* ---------- Equality between owned and borrowed keys -------------------- */
/* DashMap uses the == operator between &K and &Q, so we implement the      */
/* obvious comparisons by hand.                                             */

impl PartialEq<MacAddr6> for ReservationKey {
    fn eq(&self, other: &MacAddr6) -> bool {
        matches!(self, ReservationKey::Mac(m) if m == other)
    }
}
impl PartialEq<ReservationKey> for MacAddr6 {
    fn eq(&self, other: &ReservationKey) -> bool {
        other == self
    }
}

impl PartialEq<Duid> for ReservationKey {
    fn eq(&self, other: &Duid) -> bool {
        matches!(self, ReservationKey::Duid(d) if d == other)
    }
}
impl PartialEq<ReservationKey> for Duid {
    fn eq(&self, other: &ReservationKey) -> bool {
        other == self
    }
}

impl PartialEq<Option82> for ReservationKey {
    fn eq(&self, other: &Option82) -> bool {
        matches!(self, ReservationKey::Opt82(o) if o == other)
    }
}
impl PartialEq<ReservationKey> for Option82 {
    fn eq(&self, other: &ReservationKey) -> bool {
        other == self
    }
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
    }

    pub fn load_reservations(&self, reservations: Vec<Reservation>) {
        for reservation in reservations.into_iter() {
            self.insert(reservation);
        }
    }

    pub fn by_mac(&self, mac: &MacAddr6) -> Option<Arc<Reservation>> {
        self.inner.get(mac).map(|r| Arc::clone(r.value()))
    }

    pub fn by_duid(&self, duid: &Duid) -> Option<Arc<Reservation>> {
        self.inner.get(duid).map(|r| Arc::clone(r.value()))
    }

    pub fn by_opt82(&self, opt: &Option82) -> Option<Arc<Reservation>> {
        self.inner.get(opt).map(|r| Arc::clone(r.value()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use advmac::MacAddr6;
    use dashmap::DashMap;

    #[test]
    fn test_mac_borrow() {
        let key = ReservationKey::Mac(MacAddr6::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]));
        let borrowed: &MacAddr6 = key.borrow();
        assert_eq!(
            borrowed,
            &MacAddr6::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])
        );
    }

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

        assert_eq!(*map.get(&mac).unwrap().value(), "alice");
        assert_eq!(*map.get(&duid).unwrap().value(), "bob");
        assert_eq!(*map.get(&opt82).unwrap().value(), "charlie");
    }

    #[test]
    fn test_reservation_lookups() {
        let db = ReservationDb::new();

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
                "duid": "00:11:22:33:44:55:66",
                "option82": {"subscriber": "subscriber:1020"}
            }
        ]
        "#;
        let reservations: Vec<Reservation> = serde_json::from_str(json_str).unwrap();
        for reservation in reservations.into_iter() {
            db.insert(reservation);
        }

        assert_eq!(
            db.by_mac(&MacAddr6::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
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
