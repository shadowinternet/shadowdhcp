use crate::analytics::events::DhcpEvent;
use std::sync::mpsc;
use std::{
    fmt::Debug,
    io::{BufWriter, Write},
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};
use tracing::info;

const MAX_BATCH: usize = 256;
const MAX_BATCH_LATENCY: Duration = Duration::from_secs(3);
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(3);

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

pub fn tcp_writer<A: ToSocketAddrs + Debug>(address: A, rx: mpsc::Receiver<DhcpEvent>) {
    let mut writer: Option<Writer> = None;
    let mut batch: Vec<DhcpEvent> = Vec::with_capacity(MAX_BATCH);
    let mut dropped: u64 = 0;

    info!("Starting analytics writer sending to {:?}", address);
    loop {
        // Block for the first event
        let first = match rx.recv() {
            Ok(ev) => ev,
            Err(_) => {
                if let Some(mut w) = writer {
                    let _ = w.writer.flush();
                }
                return;
            }
        };

        batch.clear();
        batch.push(first);

        let batch_start = Instant::now();

        // Fill batch until size or latency bound
        while batch.len() < MAX_BATCH {
            let elapsed = batch_start.elapsed();

            if elapsed >= MAX_BATCH_LATENCY {
                break;
            }

            let remaining = MAX_BATCH_LATENCY - elapsed;

            match rx.recv_timeout(remaining) {
                Ok(ev) => {
                    if batch.len() < MAX_BATCH {
                        batch.push(ev);
                    } else {
                        dropped += 1;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        // Ensure connection and send
        loop {
            match writer {
                None => match Writer::connect(&address) {
                    Ok(w) => writer = Some(w),
                    Err(_) => {
                        // Drain pending events to prevent unbounded memory growth
                        while let Ok(_) = rx.try_recv() {
                            dropped += 1;
                        }
                        std::thread::sleep(RECONNECT_TIMEOUT);
                    }
                },
                Some(ref mut w) => match w.send_batch(&batch) {
                    Ok(_) => break,
                    Err(_) => {
                        writer = None;
                        // Drain pending events to prevent unbounded memory growth
                        while let Ok(_) = rx.try_recv() {
                            dropped += 1;
                        }
                        std::thread::sleep(RECONNECT_TIMEOUT);
                    }
                },
            }
        }

        // Optional metrics
        if dropped > 0 {
            tracing::warn!("Dropped {} DHCP events", dropped);
            dropped = 0;
        }
    }
}
