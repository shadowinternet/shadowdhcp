//! Cooperative shutdown flag shared by every long-running thread.
//!
//! `signal()` is called once (from the Unix signal handler on
//! SIGTERM/SIGINT); each thread either polls `is_signalled()` between
//! blocking-with-timeout operations or parks on `wait_timeout()`. On
//! Windows there is currently no console handler, so the flag is never
//! set and Ctrl-C terminates the process immediately, as before.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Clone, Default)]
pub struct Shutdown(Arc<Inner>);

#[derive(Default)]
struct Inner {
    flag: AtomicBool,
    mutex: Mutex<()>,
    condvar: Condvar,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn signal(&self) {
        self.0.flag.store(true, Ordering::SeqCst);
        // Take the mutex so the store can't slip between a waiter's
        // flag re-check and its wait.
        let _guard = self.0.mutex.lock().expect("shutdown mutex poisoned");
        self.0.condvar.notify_all();
    }

    pub fn is_signalled(&self) -> bool {
        self.0.flag.load(Ordering::SeqCst)
    }

    /// Sleep up to `dur`, waking early on `signal()`. Returns true if
    /// shutdown has been signalled.
    pub fn wait_timeout(&self, dur: Duration) -> bool {
        let guard = self.0.mutex.lock().expect("shutdown mutex poisoned");
        if self.is_signalled() {
            return true;
        }
        let _unused = self
            .0
            .condvar
            .wait_timeout(guard, dur)
            .expect("shutdown mutex poisoned");
        self.is_signalled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_returns_early_on_signal() {
        let s = Shutdown::new();
        let s2 = s.clone();
        let start = std::time::Instant::now();
        let t = std::thread::spawn(move || s2.wait_timeout(Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(50));
        s.signal();
        assert!(t.join().unwrap());
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(s.is_signalled());
    }

    #[test]
    fn wait_times_out_without_signal() {
        let s = Shutdown::new();
        assert!(!s.wait_timeout(Duration::from_millis(10)));
        assert!(!s.is_signalled());
    }
}
