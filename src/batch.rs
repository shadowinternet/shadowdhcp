//! Shared batched-flush retry loop used by analytics and logging writer threads.
//!
//! Each writer is a `BatchSink<T>`: it buffers items received from a bounded
//! channel up to a size or latency bound and flushes once per cycle. The `run`
//! function owns the receive/batch/retry state machine so the three writers
//! (TCP, ClickHouse events, ClickHouse logs) don't each reimplement it.
//!
//! Drop policy: the in-flight batch is never grown during retry. The bounded
//! channel between producers and the sink absorbs events while we retry; a
//! full channel drops at the producer. If retries are exhausted, the
//! in-flight batch is dropped via `on_giveup`. On shutdown (channel
//! disconnected), remaining buffered events are flushed best-effort: each
//! batch gets one attempt, and we exit on the first failure.

use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct BatchConfig {
    pub max_batch: usize,
    pub max_latency: Duration,
    pub retry_sleep: Duration,
    /// Cap on retries for a single failed batch during normal operation.
    /// Hitting this drops the in-flight batch via `on_giveup` so a wedged
    /// downstream can't pin one batch in memory forever. Sized so that
    /// `max_retries * retry_sleep` covers expected maintenance windows.
    pub max_retries: u32,
}

pub trait BatchSink<T> {
    fn reset(&mut self);
    fn push(&mut self, item: T);
    fn item_count(&self) -> usize;
    /// Send the buffered batch downstream. On `Err`, the runner sleeps and
    /// retries. The sink is responsible for clearing any sub-batches that
    /// have already been delivered so retries don't duplicate them.
    fn flush(&mut self) -> Result<(), ()>;

    fn on_start(&mut self) {}
    /// Called after each successful flush cycle. Sinks that maintain
    /// out-of-band counters (e.g. producer-side drop counts) can surface
    /// them here.
    fn on_cycle_complete(&mut self) {}
    /// Called when the runner is dropping the in-flight batch — either
    /// because retries were exhausted or because the channel disconnected
    /// and the best-effort shutdown flush failed. Sinks should log the
    /// loss; buffers are cleared by the next cycle's `reset`.
    fn on_giveup(&mut self) {}
}

pub fn run<T, S: BatchSink<T>>(rx: mpsc::Receiver<T>, sink: &mut S, cfg: BatchConfig) {
    sink.on_start();
    let mut rng = Rng::from_time();

    loop {
        let first = match rx.recv() {
            Ok(v) => v,
            Err(_) => return,
        };
        sink.reset();
        sink.push(first);

        let start = Instant::now();
        let mut shutdown = false;
        while sink.item_count() < cfg.max_batch {
            let elapsed = start.elapsed();
            if elapsed >= cfg.max_latency {
                break;
            }
            match rx.recv_timeout(cfg.max_latency - elapsed) {
                Ok(item) => sink.push(item),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    shutdown = true;
                    break;
                }
            }
        }

        if shutdown {
            // Best-effort drain on shutdown: one attempt, exit on failure.
            // Any remaining buffered events come through the next outer
            // `recv()`, which returns `Disconnected` once the channel is
            // empty.
            if sink.item_count() > 0 && sink.flush().is_err() {
                sink.on_giveup();
                return;
            }
            sink.on_cycle_complete();
        } else {
            flush_with_retry(sink, &cfg, &mut rng);
            sink.on_cycle_complete();
        }
    }
}

fn flush_with_retry<T, S: BatchSink<T>>(sink: &mut S, cfg: &BatchConfig, rng: &mut Rng) {
    if sink.item_count() == 0 {
        return;
    }
    let mut attempts: u32 = 0;
    loop {
        if sink.flush().is_ok() {
            return;
        }
        attempts += 1;
        if attempts >= cfg.max_retries {
            sink.on_giveup();
            return;
        }
        std::thread::sleep(cfg.retry_sleep + rng.jitter(Duration::from_secs(1)));
    }
}

/// Tiny xorshift64 PRNG, seeded from the system clock. Used only for retry
/// jitter — nothing here needs cryptographic quality.
struct Rng(u64);

impl Rng {
    fn from_time() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        // xorshift collapses on a zero state
        Self(nanos | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn jitter(&mut self, max: Duration) -> Duration {
        let bound = (max.as_nanos() as u64).max(1);
        Duration::from_nanos(self.next() % bound)
    }
}
