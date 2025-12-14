use std::sync::Arc;

use crate::{
    leasedb::LeaseDb, reservationdb::ReservationDb, v6::extensions::ShadowRelayMessageExtV6, Duid,
    Reservation,
};
use dhcproto::v6::RelayMessage;

/// Attempt to find a reservation using different lookup priorities:
///
/// 1. By DUID
/// 2. By Option 18/37 (relay agent options)
/// 3. By MAC (option 82 fallback)
pub fn find_reservation<'r>(
    reservations: &'r ReservationDb,
    leases: &'r LeaseDb,
    relay_msg: &RelayMessage,
    client_id: &Duid,
) -> Option<Arc<Reservation>> {
    reservations
        .by_duid(client_id)
        .or_else(|| {
            relay_msg
                .option1837()
                .and_then(|opt1837| reservations.by_opt1837(&opt1837))
        })
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
