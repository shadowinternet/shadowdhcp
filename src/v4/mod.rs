pub mod extensions;
pub mod handlers;
mod reservation;
pub mod worker;

const ADDRESS_LEASE_TIME: u32 = 3600;

pub use worker::v4_worker;

#[cfg(test)]
mod tests;
