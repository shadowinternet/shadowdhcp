use std::sync::Arc;

use advmac::MacAddr6;
use compact_str::CompactString;
use dhcproto::v4::relay::RelayAgentInformation;
use shadow_dhcpv6::{Option82, RelayAgentInformationExt, Reservation};
use tracing::debug;

use super::extractors::NamedOption82Extractor;
use crate::analytics::events::ReservationMatch;
use crate::reservationdb::ReservationDb;

/// Attempt to find a reservation using Option 82 relay agent information.
///
/// Tries each configured extractor in order until one finds a matching reservation.
/// Returns the reservation along with match metadata (which extractor was used).
pub fn find_reservation_by_relay_info(
    reservations: &ReservationDb,
    extractors: &[NamedOption82Extractor],
    relay: &RelayAgentInformation,
) -> Option<(Arc<Reservation>, ReservationMatch)> {
    let circuit = relay
        .circuit_id()
        .and_then(|v| CompactString::from_utf8(v).ok());
    let remote = relay
        .remote_id()
        .and_then(|v| CompactString::from_utf8(v).ok());
    let subscriber = relay
        .subscriber_id()
        .and_then(|v| CompactString::from_utf8(v).ok());

    let option = Option82 {
        circuit,
        remote,
        subscriber,
    };

    debug!("{option:?}");

    extractors.iter().find_map(|(name, extractor)| {
        extractor(&option).and_then(|extracted_opt| {
            reservations
                .by_opt82(&extracted_opt)
                .map(|res| (res, ReservationMatch::option82(name)))
        })
    })
}

/// Attempt to find a reservation using different lookup priorities:
///
/// 1. By MAC address (from chaddr)
/// 2. By Option 82 (relay agent information) using extractors
///
/// Returns the reservation along with match metadata (method and extractor used).
pub fn find_reservation(
    reservations: &ReservationDb,
    extractors: &[NamedOption82Extractor],
    mac_addr: MacAddr6,
    relay: Option<&RelayAgentInformation>,
) -> Option<(Arc<Reservation>, ReservationMatch)> {
    // Priority 1: MAC address
    if let Some(res) = reservations.by_mac(mac_addr) {
        return Some((res, ReservationMatch::mac()));
    }

    // Priority 2: Option 82 with extractors
    if let Some(result) = relay
        .and_then(|relay_info| find_reservation_by_relay_info(reservations, extractors, relay_info))
    {
        return Some(result);
    }

    None
}
