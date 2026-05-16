//! Shared HTTP layer for the ClickHouse writers (events + logs).
//!
//! Both writers POST JSONEachRow batches over HTTPS to a self-hosted
//! ClickHouse server. The differences between them are the URL, the row
//! shape, and how diagnostics are emitted (`warn!` vs `eprintln!`); the
//! transport is identical, so it lives here.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use ureq::Agent;

/// Total budget per request, including connect + send + read. Bounds how long
/// a single hung request can block the writer thread before the retry loop
/// gets another chance to drain the producer channel.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Connect-phase timeout. Shorter than the global so a dead host is detected
/// quickly instead of eating the whole 10s budget on TCP retransmits.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Outcome of a POST. Callers use this to decide whether to retry, drop the
/// batch, or move on. Splitting this on the writer side keeps the runner in
/// `crate::batch` HTTP-agnostic.
pub enum PostOutcome {
    Ok,
    /// HTTP status the server is unlikely to recover from on retry (4xx other
    /// than 408/429). Schema mismatches and auth failures land here — the
    /// caller should drop the batch with a warning instead of looping
    /// forever.
    Permanent(u16),
    /// Network error or 5xx/408/429. Worth retrying.
    Transient(String),
}

/// POST `body` to `url` and classify the response.
pub fn post(agent: &Agent, url: &str, auth: &str, body: &[u8]) -> PostOutcome {
    match agent
        .post(url)
        .header("Authorization", auth)
        .header("Content-Type", "application/x-ndjson")
        .send(body)
    {
        Ok(resp) if resp.status().is_success() => PostOutcome::Ok,
        Ok(resp) => {
            let status = resp.status().as_u16();
            if is_transient_http(status) {
                PostOutcome::Transient(format!("HTTP {status}"))
            } else {
                PostOutcome::Permanent(status)
            }
        }
        Err(e) => PostOutcome::Transient(format!("POST failed: {e}")),
    }
}

/// 408 (request timeout) and 429 (too many requests) can recover; everything
/// else in 4xx is a client error that won't fix itself by retrying.
fn is_transient_http(status: u16) -> bool {
    status == 408 || status == 429 || (500..600).contains(&status)
}

pub fn basic_auth_header(user: &str, password: &str) -> String {
    let encoded = STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {encoded}")
}

/// /etc/hostname is a one-liner on Linux/BSD. Empty on macOS/Windows is fine
/// — the ClickHouse schema defaults `host_name` to `''`.
pub fn read_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Build the shared ureq agent used by both writers.
pub fn build_agent() -> Agent {
    Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .build()
        .into()
}
