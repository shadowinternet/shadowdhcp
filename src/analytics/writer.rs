use crate::analytics::batch::{run, BatchConfig, BatchSink};
use crate::analytics::events::DhcpEvent;
use crate::shutdown::Shutdown;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::{
    fmt::Debug,
    io::{BufWriter, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};
use tracing::{info, warn};

const MAX_BATCH: usize = 256;
const MAX_BATCH_LATENCY: Duration = Duration::from_secs(3);
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Sized so that `MAX_RETRIES * RECONNECT_TIMEOUT` (~5–6 min with jitter)
/// covers short downstream maintenance windows without dropping the
/// in-flight batch.
const MAX_RETRIES: u32 = 100;

struct Writer {
    writer: BufWriter<TcpStream>,
}

impl Writer {
    fn connect<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;

        Ok(Self {
            writer: BufWriter::new(stream),
        })
    }

    fn send_batch(&mut self, batch: &[DhcpEvent]) -> std::io::Result<()> {
        for ev in batch {
            serde_json::to_writer(&mut self.writer, ev)?;
            self.writer.write_all(b"\n")?;
        }

        self.writer.flush()?;
        Ok(())
    }
}

struct TcpSink<A: ToSocketAddrs + Debug> {
    address: A,
    writer: Option<Writer>,
    batch: Vec<DhcpEvent>,
    dropped: Arc<AtomicU64>,
}

impl<A: ToSocketAddrs + Debug> BatchSink<DhcpEvent> for TcpSink<A> {
    fn reset(&mut self) {
        self.batch.clear();
    }

    fn push(&mut self, ev: DhcpEvent) {
        self.batch.push(ev);
    }

    fn item_count(&self) -> usize {
        self.batch.len()
    }

    fn flush(&mut self) -> Result<(), ()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        if self.writer.is_none() {
            match Writer::connect(&self.address) {
                Ok(w) => self.writer = Some(w),
                Err(_) => return Err(()),
            }
        }
        let w = self.writer.as_mut().expect("writer present after connect");
        match w.send_batch(&self.batch) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.writer = None;
                Err(())
            }
        }
    }

    fn on_start(&mut self) {
        info!("Starting analytics writer sending to {:?}", self.address);
    }

    fn on_cycle_complete(&mut self) {
        let n = self.dropped.swap(0, Ordering::Relaxed);
        if n > 0 {
            warn!("Dropped {n} DHCP events at sender (channel full)");
        }
    }

    fn on_giveup(&mut self) {
        if !self.batch.is_empty() {
            warn!(
                "TCP writer dropped batch of {} after exhausted retries",
                self.batch.len()
            );
        }
    }
}

pub fn tcp_writer<A: ToSocketAddrs + Debug>(
    address: A,
    rx: mpsc::Receiver<DhcpEvent>,
    dropped: Arc<AtomicU64>,
    shutdown: Shutdown,
) {
    let mut sink = TcpSink {
        address,
        writer: None,
        batch: Vec::with_capacity(MAX_BATCH),
        dropped,
    };
    run(
        rx,
        &mut sink,
        BatchConfig {
            max_batch: MAX_BATCH,
            max_latency: MAX_BATCH_LATENCY,
            retry_sleep: RECONNECT_TIMEOUT,
            max_retries: MAX_RETRIES,
        },
        &shutdown,
    );
    if let Some(mut w) = sink.writer {
        let _ = w.writer.flush();
    }
}
