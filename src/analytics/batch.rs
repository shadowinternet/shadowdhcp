//! Shared batched-flush retry loop used by the analytics writer threads.
//!
//! Each writer is a `BatchSink<T>`: it buffers items received from a bounded
//! channel up to a size or latency bound and flushes once per cycle. The `run`
//! function owns the receive/batch/retry state machine so the two writers
//! (TCP, ClickHouse events) don't each reimplement it.
//!
//! Drop policy: the in-flight batch is never grown during retry. The bounded
//! channel between producers and the sink absorbs events while we retry; a
//! full channel drops at the producer. If retries are exhausted, the
//! in-flight batch is dropped via `on_giveup`. On shutdown — the channel
//! disconnecting (all producers dropped their senders) or the process-wide
//! `Shutdown` flag being signalled — remaining buffered events are flushed
//! best-effort: each batch gets one attempt, and we exit on the first
//! failure. The flag also interrupts retry sleeps, so SIGTERM isn't delayed
//! by a wedged downstream.

use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::shutdown::Shutdown;

/// How often the idle outer loop wakes to check the shutdown flag.
const SHUTDOWN_POLL: Duration = Duration::from_millis(500);
/// How long the shutdown drain waits for a quiet channel before the final
/// flush. Producers (the DHCP workers) notice the flag within ~1 s of the
/// signal, so a 2 s idle window outlives anything still in flight.
const SHUTDOWN_QUIET: Duration = Duration::from_secs(2);

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

pub fn run<T, S: BatchSink<T>>(
    rx: mpsc::Receiver<T>,
    sink: &mut S,
    cfg: BatchConfig,
    shutdown: &Shutdown,
) {
    sink.on_start();
    let mut rng = Rng::from_time();

    loop {
        if shutdown.is_signalled() {
            drain_on_shutdown(&rx, sink, &cfg);
            return;
        }
        let first = match rx.recv_timeout(SHUTDOWN_POLL) {
            Ok(v) => v,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        sink.reset();
        sink.push(first);

        let start = Instant::now();
        let mut stopping = false;
        while sink.item_count() < cfg.max_batch {
            let elapsed = start.elapsed();
            if elapsed >= cfg.max_latency {
                break;
            }
            match rx.recv_timeout(cfg.max_latency - elapsed) {
                Ok(item) => {
                    sink.push(item);
                    if shutdown.is_signalled() {
                        stopping = true;
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if shutdown.is_signalled() {
                        stopping = true;
                    }
                    break;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    stopping = true;
                    break;
                }
            }
        }

        if stopping {
            // Best-effort flush on shutdown: one attempt, exit on failure.
            // Anything still in the channel is handled by the next outer
            // iteration — the shutdown-flag drain or a `Disconnected` recv.
            if sink.item_count() > 0 && sink.flush().is_err() {
                sink.on_giveup();
                return;
            }
            sink.on_cycle_complete();
        } else {
            flush_with_retry(sink, &cfg, &mut rng, shutdown);
            sink.on_cycle_complete();
        }
    }
}

/// Final drain after the shutdown flag is raised: keep receiving until the
/// channel is quiet or disconnected, then flush once, best-effort.
fn drain_on_shutdown<T, S: BatchSink<T>>(rx: &mpsc::Receiver<T>, sink: &mut S, cfg: &BatchConfig) {
    sink.reset();
    // Stop on either RecvTimeoutError: quiet or disconnected, we're done.
    while let Ok(item) = rx.recv_timeout(SHUTDOWN_QUIET) {
        sink.push(item);
        if sink.item_count() >= cfg.max_batch {
            if sink.flush().is_err() {
                sink.on_giveup();
                return;
            }
            sink.reset();
        }
    }
    if sink.item_count() > 0 && sink.flush().is_err() {
        sink.on_giveup();
    }
    sink.on_cycle_complete();
}

fn flush_with_retry<T, S: BatchSink<T>>(
    sink: &mut S,
    cfg: &BatchConfig,
    rng: &mut Rng,
    shutdown: &Shutdown,
) {
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
        // Sleep on the shutdown condvar so SIGTERM interrupts a
        // downstream-outage retry loop immediately instead of pinning the
        // process exit for up to max_retries * retry_sleep (~5 min).
        if shutdown.wait_timeout(cfg.retry_sleep + rng.jitter(Duration::from_secs(1))) {
            sink.on_giveup();
            return;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// TCP-style sink: `flush` copies the buffer out without clearing it,
    /// relying on the runner's `reset` discipline (like `TcpSink`). This
    /// makes the test double-count if the runner ever flushes twice without
    /// a reset in between.
    #[derive(Default)]
    struct TestSink {
        buf: Vec<u32>,
        flushed: Vec<u32>,
        flushes: usize,
        fail: bool,
        gaveup: bool,
    }

    impl BatchSink<u32> for TestSink {
        fn reset(&mut self) {
            self.buf.clear();
        }
        fn push(&mut self, v: u32) {
            self.buf.push(v);
        }
        fn item_count(&self) -> usize {
            self.buf.len()
        }
        fn flush(&mut self) -> Result<(), ()> {
            self.flushes += 1;
            if self.fail {
                return Err(());
            }
            self.flushed.extend_from_slice(&self.buf);
            Ok(())
        }
        fn on_giveup(&mut self) {
            self.gaveup = true;
        }
    }

    fn test_cfg(max_batch: usize) -> BatchConfig {
        BatchConfig {
            max_batch,
            max_latency: Duration::from_millis(10),
            retry_sleep: Duration::from_secs(5),
            max_retries: 100,
        }
    }

    #[test]
    fn shutdown_drains_entire_backlog_not_just_one_batch() {
        let (tx, rx) = mpsc::sync_channel::<u32>(4096);
        for i in 0..2000 {
            tx.send(i).unwrap();
        }
        drop(tx);

        let shutdown = Shutdown::new();
        shutdown.signal(); // flag already set: run() goes straight to drain

        let mut sink = TestSink::default();
        run(rx, &mut sink, test_cfg(256), &shutdown);

        assert_eq!(sink.flushed, (0..2000).collect::<Vec<u32>>());
        // 7 full 256-item flushes + one final 208-item flush
        assert_eq!(sink.flushes, 8);
        assert!(!sink.gaveup);
    }

    #[test]
    fn drain_stops_at_first_failed_flush() {
        let (tx, rx) = mpsc::sync_channel::<u32>(4096);
        for i in 0..500 {
            tx.send(i).unwrap();
        }
        drop(tx);

        let shutdown = Shutdown::new();
        shutdown.signal();

        let mut sink = TestSink {
            fail: true,
            ..TestSink::default()
        };
        let start = Instant::now();
        run(rx, &mut sink, test_cfg(256), &shutdown);

        // One attempt at the first full batch, then give up — no retry sleeps.
        assert_eq!(sink.flushes, 1);
        assert!(sink.gaveup);
        assert!(sink.flushed.is_empty());
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn shutdown_interrupts_retry_loop() {
        let (tx, rx) = mpsc::sync_channel::<u32>(16);
        tx.send(1).unwrap();

        let shutdown = Shutdown::new();
        let signaller = shutdown.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            signaller.signal();
            drop(tx); // ends the subsequent drain immediately
        });

        // fail=true: the first flush fails and the runner enters
        // flush_with_retry with retry_sleep=5s, max_retries=100 (~8 min of
        // retries). The signal at t=100ms must cut that short.
        let mut sink = TestSink {
            fail: true,
            ..TestSink::default()
        };
        let start = Instant::now();
        run(rx, &mut sink, test_cfg(256), &shutdown);
        t.join().unwrap();

        assert!(sink.gaveup);
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "retry loop was not interrupted by shutdown (took {:?})",
            start.elapsed()
        );
    }
}
