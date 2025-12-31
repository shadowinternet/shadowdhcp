pub mod extensions;
pub mod extractors;
pub mod handlers;
pub mod mac_extractors;
mod reservation;
pub mod worker;

/// Valid Lifetime - total time the lease is valid (the "lease time")
/// This is the primary value - all other lifetimes are derived from it.
pub(crate) const VALID_LIFETIME: u32 = 7200;
/// Preferred Lifetime - time until address becomes "deprecated" (typically 0.5 * valid_lifetime)
pub(crate) const PREFERRED_LIFETIME: u32 = VALID_LIFETIME / 2;
/// Renewal Time - T1 - time until client enters RENEWING state (typically 0.5 * preferred_lifetime)
/// RFC 8415 Section 21.4, 21.21
pub(crate) const RENEWAL_TIME: u32 = PREFERRED_LIFETIME / 2;
/// Rebinding Time - T2 - time until client enters REBINDING state (typically 0.8 * preferred_lifetime)
/// RFC 8415 Section 21.4, 21.21
pub(crate) const REBINDING_TIME: u32 = PREFERRED_LIFETIME * 4 / 5;

pub use worker::v6_worker;

#[cfg(test)]
mod tests;
