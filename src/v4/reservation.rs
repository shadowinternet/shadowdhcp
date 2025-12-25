use std::sync::Arc;

use compact_str::CompactString;
use dhcproto::v4::relay::RelayAgentInformation;
use shadow_dhcpv6::{Option82, RelayAgentInformationExt, Reservation};
use tracing::debug;

use super::extractors::Option82ExtractorFn;
use crate::reservationdb::ReservationDb;

/// Attempt to find a reservation using Option 82 relay agent information.
///
/// Tries each configured extractor in order until one finds a matching reservation.
pub fn find_reservation_by_relay_info(
    reservations: &ReservationDb,
    extractors: &[Option82ExtractorFn],
    relay: &RelayAgentInformation,
) -> Option<Arc<Reservation>> {
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

    extractors.iter().find_map(|extractor| {
        extractor(&option).and_then(|extracted_opt| reservations.by_opt82(&extracted_opt))
    })
}
