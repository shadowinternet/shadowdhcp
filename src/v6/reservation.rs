use std::sync::Arc;

use dhcproto::v6::{Message, RelayMessage};
use shadowdhcp::{Duid, Reservation};
use tracing::debug;

use crate::analytics::events::ReservationMatch;
use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;

use super::extensions::ShadowRelayMessageExtV6;
use super::extractors::NamedOption1837Extractor;
use super::mac_extractors::MacExtractor;

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
/// 3. By MAC (using configured extractors in order)
/// 4. By Option82 (via MAC lookup in lease database - fallback for each extracted MAC)
///
/// Returns the reservation along with match metadata (method and extractor used).
pub fn find_reservation(
    reservations: &ReservationDb,
    leases: &LeaseDb,
    opt1837_extractors: &[NamedOption1837Extractor],
    mac_extractors: &[MacExtractor],
    relay_msg: &RelayMessage,
    msg: &Message,
    client_id: &Duid,
) -> Option<(Arc<Reservation>, ReservationMatch)> {
    // Priority 1: DUID
    if let Some(res) = reservations.by_duid(client_id) {
        return Some((res, ReservationMatch::duid()));
    }

    // Priority 2: Option 18/37 with extractors
    if let Some(result) =
        find_reservation_by_relay_info(reservations, opt1837_extractors, relay_msg)
    {
        return Some(result);
    }

    // Priority 3: Try MAC extractors in order
    for extractor in mac_extractors {
        if let Some(mac) = extractor.extract(relay_msg, msg) {
            // Try direct MAC reservation match
            if let Some(res) = reservations.by_mac(mac) {
                return Some((res, ReservationMatch::mac(extractor.name())));
            }
            // Priority 4: Option82 via lease fallback
            if let Some(opt82) = leases.get_opt82_by_mac(&mac) {
                if let Some(res) = reservations.by_opt82(&opt82) {
                    return Some((res, ReservationMatch::option82("lease_fallback")));
                }
            }
        }
    }

    None
}
