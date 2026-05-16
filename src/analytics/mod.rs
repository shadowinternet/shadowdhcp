pub mod events;
pub mod writer;

#[cfg(feature = "clickhouse")]
pub mod clickhouse;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

use crate::analytics::events::DhcpEvent;

/// Per-sink fan-out target: the bounded channel and a drop counter shared
/// with the writer thread so it can report producer-side drops on each cycle.
#[derive(Clone)]
struct EventSinkChannel {
    tx: mpsc::SyncSender<DhcpEvent>,
    dropped: Arc<AtomicU64>,
}

/// Fan-out to every enabled event sink. Channels are bounded; a full queue
/// drops the event at the producer rather than back-pressuring the DHCP hot
/// path. Each drop is counted in the sink's shared `dropped` counter, which
/// the writer thread reads and logs once per flush cycle.
#[derive(Clone, Default)]
pub struct EventSenders(Vec<EventSinkChannel>);

impl EventSenders {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, tx: mpsc::SyncSender<DhcpEvent>, dropped: Arc<AtomicU64>) {
        self.0.push(EventSinkChannel { tx, dropped });
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn send(&self, event: DhcpEvent) {
        // Move `event` into the last sink instead of cloning, so the common
        // single-sink case doesn't clone at all.
        let Some((last, rest)) = self.0.split_last() else {
            return;
        };

        for sink in rest {
            if sink.tx.try_send(event.clone()).is_err() {
                sink.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        if last.tx.try_send(event).is_err() {
            last.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}
