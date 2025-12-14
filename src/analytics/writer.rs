// src/analytics/writer.rs

use clickhouse::{Client, Row};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};

use crate::middleware::analytics::{AnalyticsEvent, DhcpEventV4, DhcpEventV6};

const BATCH_SIZE: usize = 1000;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

pub struct ClickHouseWriter {
    client: Client,
    receiver: mpsc::Receiver<AnalyticsEvent>,
    table_v4: String,
    table_v6: String,
}

impl ClickHouseWriter {
    pub fn new(
        client: Client,
        receiver: mpsc::Receiver<AnalyticsEvent>,
        table_v4: impl Into<String>,
        table_v6: impl Into<String>,
    ) -> Self {
        Self {
            client,
            receiver,
            table_v4: table_v4.into(),
            table_v6: table_v6.into(),
        }
    }

    pub async fn run(mut self) {
        let mut batch_v4: Vec<DhcpEventV4> = Vec::with_capacity(BATCH_SIZE);
        let mut batch_v6: Vec<DhcpEventV6> = Vec::with_capacity(BATCH_SIZE);
        let mut flush_interval = interval(FLUSH_INTERVAL);

        loop {
            tokio::select! {
                // Receive events
                event = self.receiver.recv() => {
                    match event {
                        Some(AnalyticsEvent::V4(e)) => batch_v4.push(e),
                        Some(AnalyticsEvent::V6(e)) => batch_v6.push(e),
                        None => {
                            // Channel closed, flush and exit
                            self.flush_v4(&mut batch_v4).await;
                            self.flush_v6(&mut batch_v6).await;
                            info!("Analytics writer shutting down");
                            return;
                        }
                    }

                    // Flush if batch is large enough
                    if batch_v4.len() >= BATCH_SIZE {
                        self.flush_v4(&mut batch_v4).await;
                    }
                    if batch_v6.len() >= BATCH_SIZE {
                        self.flush_v6(&mut batch_v6).await;
                    }
                }

                // Periodic flush
                _ = flush_interval.tick() => {
                    if !batch_v4.is_empty() {
                        self.flush_v4(&mut batch_v4).await;
                    }
                    if !batch_v6.is_empty() {
                        self.flush_v6(&mut batch_v6).await;
                    }
                }
            }
        }
    }

    async fn flush_v4(&self, batch: &mut Vec<DhcpEventV4>) {
        if batch.is_empty() {
            return;
        }

        let count = batch.len();
        match self
            .insert_batch(&self.table_v4, batch.drain(..).collect())
            .await
        {
            Ok(()) => debug!("Flushed {} v4 events to ClickHouse", count),
            Err(e) => error!("Failed to flush v4 events: {}", e),
        }
    }

    async fn flush_v6(&self, batch: &mut Vec<DhcpEventV6>) {
        if batch.is_empty() {
            return;
        }

        let count = batch.len();
        match self
            .insert_batch(&self.table_v6, batch.drain(..).collect())
            .await
        {
            Ok(()) => debug!("Flushed {} v6 events to ClickHouse", count),
            Err(e) => error!("Failed to flush v6 events: {}", e),
        }
    }

    async fn insert_batch<T: Row>(
        &self,
        _table: &str,
        _rows: Vec<T>,
    ) -> Result<(), clickhouse::error::Error> {
        //let mut insert: clickhouse::insert::Insert<T> = self.client.insert(table).await?;
        //for row in rows {
        //    insert.write(&row).await?;
        //}
        //insert.end().await?;
        //Ok(())
        todo!()
    }
}

/// Alternative: Use ClickHouse's built-in inserter for better batching
pub struct ClickHouseInserterWriter {
    receiver: mpsc::Receiver<AnalyticsEvent>,
    inserter_v4: clickhouse::inserter::Inserter<DhcpEventV4>,
    inserter_v6: clickhouse::inserter::Inserter<DhcpEventV6>,
}

impl ClickHouseInserterWriter {
    pub async fn new(
        client: Client,
        receiver: mpsc::Receiver<AnalyticsEvent>,
        table_v4: &str,
        table_v6: &str,
    ) -> Result<Self, clickhouse::error::Error> {
        let inserter_v4 = client
            .inserter(table_v4)
            .with_max_rows(BATCH_SIZE as u64)
            .with_period(Some(FLUSH_INTERVAL));

        let inserter_v6 = client
            .inserter(table_v6)
            .with_max_rows(BATCH_SIZE as u64)
            .with_period(Some(FLUSH_INTERVAL));

        Ok(Self {
            receiver,
            inserter_v4,
            inserter_v6,
        })
    }

    pub async fn run(mut self) {
        loop {
            match self.receiver.recv().await {
                Some(AnalyticsEvent::V4(event)) => {
                    if let Err(e) = self.inserter_v4.write(&event).await {
                        error!("Failed to write v4 event: {}", e);
                    }
                    // Inserter handles batching internally
                    if let Err(e) = self.inserter_v4.commit().await {
                        error!("Failed to commit v4 inserter: {}", e);
                    }
                }
                Some(AnalyticsEvent::V6(event)) => {
                    if let Err(e) = self.inserter_v6.write(&event).await {
                        error!("Failed to write v6 event: {}", e);
                    }
                    if let Err(e) = self.inserter_v6.commit().await {
                        error!("Failed to commit v6 inserter: {}", e);
                    }
                }
                None => {
                    // Flush and exit
                    let _ = self.inserter_v4.end().await;
                    let _ = self.inserter_v6.end().await;
                    info!("Analytics inserter writer shutting down");
                    return;
                }
            }
        }
    }
}
