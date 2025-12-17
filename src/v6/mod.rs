pub mod extensions;
pub mod handlers;
mod reservation;
pub mod worker;

const PREFERRED_LIFETIME: u32 = 3600;
const VALID_LIFETIME: u32 = 7200;

pub use worker::v6_worker;

#[cfg(test)]
mod tests;
