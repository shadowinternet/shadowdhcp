pub mod extensions;
pub mod handlers;
mod reservation;
pub mod worker;

const ADDRESS_LEASE_TIME: u32 = 3600;
/// Renewal Time - T1 - time until client enters RENEWING state (typically 0.5 * lease_time)
const RENEWAL_TIME: u32 = ADDRESS_LEASE_TIME / 2;
/// Rebinding Time - T2 - time until client enters REBINDING state (typically 0.875 * lease_time)
const REBINDING_TIME: u32 = ADDRESS_LEASE_TIME * 7 / 8;

pub use worker::v4_worker;

#[cfg(test)]
mod tests;
