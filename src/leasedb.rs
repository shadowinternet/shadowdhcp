use std::time::{Duration, Instant};

use advmac::MacAddr6;
use dashmap::DashMap;
use tracing::info;

use shadow_dhcpv6::{LeaseV4, LeaseV6, Option82, Reservation};

/// Wrapper for Option82 with timestamp for expiry tracking
#[derive(Clone)]
struct Opt82Entry {
    opt82: Option82,
    last_seen: Instant,
}

#[derive(Clone)]
pub struct LeaseDb {
    v4: DashMap<Reservation, LeaseV4>,
    v6: DashMap<Reservation, LeaseV6>,
    mac_to_opt82: DashMap<MacAddr6, Opt82Entry>,
}

impl LeaseDb {
    pub fn new() -> Self {
        Self {
            v4: DashMap::new(),
            v6: DashMap::new(),
            mac_to_opt82: DashMap::new(),
        }
    }

    pub fn lease_v4(
        &self,
        reservation: &Reservation,
        mac: MacAddr6,
        option82: Option<Option82>,
        valid: Duration,
    ) {
        if let Some(ref opt) = option82 {
            self.insert_mac_option82_binding(&mac, &opt);
        }

        let now = Instant::now();

        self.v4
            .entry(reservation.to_owned())
            .and_modify(|entry| entry.last_leased = now)
            .or_insert_with(|| LeaseV4 {
                first_leased: now,
                last_leased: now,
                valid,
                mac,
                option82: option82,
            });
    }

    pub fn leased_new_v6(&self, reservation: &Reservation, lease: LeaseV6) {
        match self.v6.insert(reservation.to_owned(), lease.clone()) {
            Some(old_lease) => {
                info!(ipv6_na = %reservation.ipv6_na, ipv6_pd = %reservation.ipv6_pd, "replaced existing lease {old_lease:?} with new lease {lease:?}")
            }
            None => {
                info!(ipv6_na = %reservation.ipv6_na, ipv6_pd = %reservation.ipv6_pd, duid = ?lease.duid, mac = ?lease.mac, "first time leased address"
                )
            }
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

    /// Remove expired entries from the LeaseDB.
    ///
    /// - `opt82_max_age`: Maximum age for mac_to_opt82 entries (e.g., 1 day)
    pub fn evict_expired(&self, opt82_max_age: Duration) {
        let now = Instant::now();

        // Clean up expired mac -> option82 bindings
        let opt82_before = self.mac_to_opt82.len();
        self.mac_to_opt82
            .retain(|_mac, entry| now.duration_since(entry.last_seen) < opt82_max_age);
        let opt82_evicted = opt82_before - self.mac_to_opt82.len();

        // Clean up expired v4 leases
        let v4_before = self.v4.len();
        self.v4
            .retain(|_res, lease| now.duration_since(lease.last_leased) < lease.valid);
        let v4_evicted = v4_before - self.v4.len();

        // Clean up expired v6 leases
        let v6_before = self.v6.len();
        self.v6
            .retain(|_res, lease| now.duration_since(lease.last_leased) < lease.valid);
        let v6_evicted = v6_before - self.v6.len();

        if opt82_evicted > 0 || v4_evicted > 0 || v6_evicted > 0 {
            info!(
                opt82_evicted,
                v4_evicted,
                v6_evicted,
                opt82_remaining = self.mac_to_opt82.len(),
                v4_remaining = self.v4.len(),
                v6_remaining = self.v6.len(),
                "evicted expired entries"
            );
        }
    }

    /// Spawn a cleanup thread that periodically evicts expired entries.
    ///
    /// Returns a join handle for the spawned thread.
    pub fn spawn_cleanup_thread(
        &self,
        interval: Duration,
        opt82_max_age: Duration,
    ) -> std::thread::JoinHandle<()> {
        let db = self.clone();
        std::thread::Builder::new()
            .name("leasedb-cleanup".into())
            .spawn(move || loop {
                std::thread::sleep(interval);
                db.evict_expired(opt82_max_age);
            })
            .expect("failed to spawn leasedb cleanup thread")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv6Net;
    use shadow_dhcpv6::Duid;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::thread::sleep;

    fn test_reservation(id: u8) -> Reservation {
        Reservation {
            ipv4: Ipv4Addr::new(10, 0, 0, id),
            ipv6_na: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, id as u16),
            ipv6_pd: "2001:db8:1::/48".parse::<Ipv6Net>().unwrap(),
            mac: None,
            duid: None,
            option82: None,
            option1837: None,
        }
    }

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

    #[test]
    fn evict_expired_opt82() {
        let db = LeaseDb::new();
        let mac_old = test_mac(0x01);
        let mac_fresh = test_mac(0x02);

        db.insert_mac_option82_binding(&mac_old, &test_option82());
        sleep(Duration::from_millis(10));
        db.insert_mac_option82_binding(&mac_fresh, &test_option82());

        // Evict entries older than 5ms
        db.evict_expired(Duration::from_millis(5));

        assert!(
            db.get_opt82_by_mac(&mac_old).is_none(),
            "old entry should be evicted"
        );
        assert!(
            db.get_opt82_by_mac(&mac_fresh).is_some(),
            "fresh entry should remain"
        );
    }

    #[test]
    fn evict_expired_leases() {
        let db = LeaseDb::new();

        // Add expired and fresh v4 leases
        db.lease_v4(
            &test_reservation(1),
            test_mac(0x01),
            None,
            Duration::from_millis(5),
        );

        // Add expired and fresh v6 leases
        db.leased_new_v6(
            &test_reservation(2),
            LeaseV6 {
                first_leased: Instant::now(),
                last_leased: Instant::now(),
                valid: Duration::from_millis(5),
                duid: Duid { bytes: vec![0x01] },
                mac: None,
            },
        );

        sleep(Duration::from_millis(10));

        // Add fresh leases after sleep
        db.lease_v4(
            &test_reservation(3),
            test_mac(0x02),
            None,
            Duration::from_millis(3600),
        );

        db.leased_new_v6(
            &test_reservation(4),
            LeaseV6 {
                first_leased: Instant::now(),
                last_leased: Instant::now(),
                valid: Duration::from_secs(3600),
                duid: Duid { bytes: vec![0x02] },
                mac: None,
            },
        );

        db.evict_expired(Duration::from_secs(3600));

        assert_eq!(db.v4.len(), 1, "expired v4 lease should be evicted");
        assert_eq!(db.v6.len(), 1, "expired v6 lease should be evicted");
    }

    #[test]
    fn insert_mac_option82_updates_last_seen() {
        let db = LeaseDb::new();
        let mac = test_mac(0x20);

        db.insert_mac_option82_binding(&mac, &test_option82());
        sleep(Duration::from_millis(10));

        // Re-insert to update last_seen
        db.insert_mac_option82_binding(&mac, &test_option82());

        // Should survive eviction since we just updated it
        db.evict_expired(Duration::from_millis(5));
        assert!(db.get_opt82_by_mac(&mac).is_some());
    }
}
