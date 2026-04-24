pub mod events;
pub mod writer;

#[cfg(feature = "clickhouse")]
pub mod clickhouse;

use std::sync::mpsc;

use crate::analytics::events::DhcpEvent;

/// Fan-out to every enabled event sink.
#[derive(Clone, Default)]
pub struct EventSenders(Vec<mpsc::Sender<DhcpEvent>>);

impl EventSenders {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, tx: mpsc::Sender<DhcpEvent>) {
        self.0.push(tx);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn send(&self, event: DhcpEvent) {
        let mut iter = self.0.iter();
        let Some(first) = iter.next() else { return };

        let mut prev = first;
        for next in iter {
            let _ = prev.send(event.clone());
            prev = next;
        }
        let _ = prev.send(event);
    }
}
