use std::sync::Arc;

use dhcproto::v6::RelayMessage;
use shadow_dhcpv6::{Duid, Reservation};
use tracing::debug;

use crate::analytics::events::ReservationMatch;
use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;

use super::extensions::ShadowRelayMessageExtV6;
use super::extractors::NamedOption1837Extractor;

/// Attempt to find a reservation using Option 18/37 relay agent information.
///
/// Tries each configured extractor in order until one finds a matching reservation.
/// Returns the reservation along with match metadata (which extractor was used).
pub fn find_reservation_by_relay_info(
    reservations: &ReservationDb,
    extractors: &[NamedOption1837Extractor],
    relay_msg: &RelayMessage,
) -> Option<(Arc<Reservation>, ReservationMatch)> {
    let option1837 = relay_msg.option1837()?;
    debug!("{option1837:?}");

    extractors.iter().find_map(|(name, extractor)| {
        extractor(&option1837).and_then(|extracted_opt| {
            reservations
                .by_opt1837(&extracted_opt)
                .map(|res| (res, ReservationMatch::option1837(name)))
        })
    })
}

/// Attempt to find a reservation using different lookup priorities:
///
/// 1. By DUID
/// 2. By Option 18/37 (relay agent options) using extractors
/// 3. By MAC (from relay hardware address)
/// 4. By Option82 (via MAC lookup in lease database - fallback)
///
/// Returns the reservation along with match metadata (method and extractor used).
pub fn find_reservation(
    reservations: &ReservationDb,
    leases: &LeaseDb,
    extractors: &[NamedOption1837Extractor],
    relay_msg: &RelayMessage,
    client_id: &Duid,
) -> Option<(Arc<Reservation>, ReservationMatch)> {
    // Priority 1: DUID
    if let Some(res) = reservations.by_duid(client_id) {
        return Some((res, ReservationMatch::duid()));
    }

    // Priority 2: Option 18/37 with extractors
    if let Some(result) = find_reservation_by_relay_info(reservations, extractors, relay_msg) {
        return Some(result);
    }

    // Priority 3 & 4: MAC fallback, then Option82 via lease
    relay_msg.hw_addr().and_then(|mac| {
        reservations
            .by_mac(mac)
            .map(|res| (res, ReservationMatch::mac()))
            .or_else(|| {
                leases.get_opt82_by_mac(&mac).and_then(|opt82| {
                    reservations
                        .by_opt82(&opt82)
                        .map(|res| (res, ReservationMatch::option82("lease_fallback")))
                })
            })
    })
}
