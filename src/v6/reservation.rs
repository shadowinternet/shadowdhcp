use std::sync::Arc;

use dhcproto::v6::RelayMessage;
use shadow_dhcpv6::{Duid, Reservation};
use tracing::debug;

use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;

use super::extensions::ShadowRelayMessageExtV6;
use super::extractors::Option1837ExtractorFn;

/// Attempt to find a reservation using Option 18/37 relay agent information.
///
/// Tries each configured extractor in order until one finds a matching reservation.
pub fn find_reservation_by_relay_info(
    reservations: &ReservationDb,
    extractors: &[Option1837ExtractorFn],
    relay_msg: &RelayMessage,
) -> Option<Arc<Reservation>> {
    let option1837 = relay_msg.option1837()?;
    debug!("{option1837:?}");

    extractors.iter().find_map(|extractor| {
        extractor(&option1837).and_then(|extracted_opt| reservations.by_opt1837(&extracted_opt))
    })
}

/// Attempt to find a reservation using different lookup priorities:
///
/// 1. By DUID
/// 2. By Option 18/37 (relay agent options) using extractors
/// 3. By MAC (option 82 fallback)
pub fn find_reservation(
    reservations: &ReservationDb,
    leases: &LeaseDb,
    extractors: &[Option1837ExtractorFn],
    relay_msg: &RelayMessage,
    client_id: &Duid,
) -> Option<Arc<Reservation>> {
    reservations
        .by_duid(client_id)
        .or_else(|| find_reservation_by_relay_info(reservations, extractors, relay_msg))
        .or_else(|| {
            relay_msg.hw_addr().and_then(|mac| {
                reservations.by_mac(mac).or_else(|| {
                    leases
                        .get_opt82_by_mac(&mac)
                        .and_then(|opt82| reservations.by_opt82(&opt82))
                })
            })
        })
}
