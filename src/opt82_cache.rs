use std::time::{Duration, Instant};

use advmac::MacAddr6;
use dashmap::DashMap;
use tracing::info;

use crate::reservationdb::ReservationDb;
use crate::types::Option82;

/// Wrapper for Option82 with timestamp for expiry tracking.
#[derive(Clone)]
struct Opt82Entry {
    opt82: Option82,
    last_seen: Instant,
}

/// Cache mapping client MAC addresses to the most recently observed Option82
/// value. Bridges DHCPv4 option82 context into v6 reservation matching when
/// the same router does both protocols and only the MAC is shared.
#[derive(Clone)]
pub struct Opt82Cache {
    mac_to_opt82: DashMap<MacAddr6, Opt82Entry>,
}

impl Opt82Cache {
    pub fn new() -> Self {
        Self {
            mac_to_opt82: DashMap::new(),
        }
    }

    pub fn insert_mac_option82_binding(&self, mac: &MacAddr6, opt: &Option82) {
        self.mac_to_opt82
            .entry(*mac)
            .and_modify(|entry| {
                entry.last_seen = Instant::now();
            })
            .or_insert_with(|| {
                info!(%mac, option82 = ?opt, "added mac -> option82 binding");
                Opt82Entry {
                    opt82: opt.clone(),
                    last_seen: Instant::now(),
                }
            });
    }

    pub fn get_opt82_by_mac(&self, mac_addr: &MacAddr6) -> Option<Option82> {
        self.mac_to_opt82
            .get(mac_addr)
            .map(|entry| entry.opt82.clone())
    }

    /// Remove expired and orphaned mac -> option82 bindings.
    ///
    /// - `opt82_max_age`: maximum age before a binding is dropped (time-based).
    /// - `reservations`: current reservation database; bindings whose Option82
    ///   no longer corresponds to any reservation are pruned.
    pub fn evict_expired(&self, opt82_max_age: Duration, reservations: &ReservationDb) {
        let now = Instant::now();

        let before = self.mac_to_opt82.len();
        self.mac_to_opt82
            .retain(|_mac, entry| now.duration_since(entry.last_seen) < opt82_max_age);
        let expired = before - self.mac_to_opt82.len();

        let after_expire = self.mac_to_opt82.len();
        self.mac_to_opt82
            .retain(|_mac, entry| reservations.has_opt82(&entry.opt82));
        let orphaned = after_expire - self.mac_to_opt82.len();

        if expired > 0 || orphaned > 0 {
            info!(
                expired,
                orphaned,
                remaining = self.mac_to_opt82.len(),
                "evicted expired option82 bindings"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv6Net;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::thread::sleep;

    use crate::types::Reservation;

    fn test_option82() -> Option82 {
        Option82 {
            circuit: Some("circuit1".into()),
            remote: Some("remote1".into()),
            subscriber: None,
        }
    }

    fn test_mac(last_octet: u8) -> MacAddr6 {
        MacAddr6::new([0x00, 0x11, 0x22, 0x33, 0x44, last_octet])
    }

    fn reservations_with_opt82(opt82: Option82) -> ReservationDb {
        let db = ReservationDb::new();
        db.load_reservations(vec![Reservation {
            ipv4: Ipv4Addr::new(10, 0, 0, 1),
            ipv6_na: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            ipv6_pd: "2001:db8:1::/48".parse::<Ipv6Net>().unwrap(),
            mac: None,
            duid: None,
            option82: Some(opt82),
            option1837: None,
        }]);
        db
    }

    #[test]
    fn evict_expired_opt82() {
        let cache = Opt82Cache::new();
        let reservations = reservations_with_opt82(test_option82());
        let mac_old = test_mac(0x01);
        let mac_fresh = test_mac(0x02);

        cache.insert_mac_option82_binding(&mac_old, &test_option82());
        sleep(Duration::from_millis(10));
        cache.insert_mac_option82_binding(&mac_fresh, &test_option82());

        cache.evict_expired(Duration::from_millis(5), &reservations);

        assert!(
            cache.get_opt82_by_mac(&mac_old).is_none(),
            "old entry should be evicted"
        );
        assert!(
            cache.get_opt82_by_mac(&mac_fresh).is_some(),
            "fresh entry should remain"
        );
    }

    #[test]
    fn insert_mac_option82_updates_last_seen() {
        let cache = Opt82Cache::new();
        let reservations = reservations_with_opt82(test_option82());
        let mac = test_mac(0x20);

        cache.insert_mac_option82_binding(&mac, &test_option82());
        sleep(Duration::from_millis(10));

        // Re-insert to update last_seen
        cache.insert_mac_option82_binding(&mac, &test_option82());

        cache.evict_expired(Duration::from_millis(5), &reservations);
        assert!(cache.get_opt82_by_mac(&mac).is_some());
    }

    #[test]
    fn evict_orphaned_opt82_bindings() {
        let cache = Opt82Cache::new();
        let valid_opt82 = test_option82();
        let orphan_opt82 = Option82 {
            circuit: Some("orphan".into()),
            remote: None,
            subscriber: None,
        };

        let reservations = reservations_with_opt82(valid_opt82.clone());

        let valid_mac = test_mac(0x01);
        let orphan_mac = test_mac(0x02);

        cache.insert_mac_option82_binding(&valid_mac, &valid_opt82);
        cache.insert_mac_option82_binding(&orphan_mac, &orphan_opt82);

        assert_eq!(cache.mac_to_opt82.len(), 2);

        cache.evict_expired(Duration::from_secs(3600), &reservations);

        assert!(
            cache.get_opt82_by_mac(&valid_mac).is_some(),
            "binding with valid reservation should remain"
        );
        assert!(
            cache.get_opt82_by_mac(&orphan_mac).is_none(),
            "binding without reservation should be pruned"
        );
    }
}
