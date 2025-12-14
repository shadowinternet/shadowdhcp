// src/main.rs

use std::sync::Arc;

use clickhouse::Client;
use tokio::sync::mpsc;
use tower::ServiceBuilder;
use tracing::info;

mod analytics;
mod config;
mod extractors;
mod leasedb;
mod middleware;
mod reservationdb;
mod service;
mod transport;
mod types;

use crate::{service::dhcp::DhcpService, types::Reservation};
use config::Config;
use leasedb::LeaseDb;
use middleware::analytics::AnalyticsLayer;
use reservationdb::ReservationDb;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // Load config
    let config = Arc::new(Config::load_from_files(".")?);

    // Initialize databases
    let reservations = Arc::new(ReservationDb::new());
    let leases = Arc::new(LeaseDb::new());

    // Load reservations
    let reservation_data: Vec<Reservation> =
        serde_json::from_reader(std::fs::File::open("reservations.json")?)?;
    info!("Read {} reservations", reservation_data.len());
    reservations.load_reservations(reservation_data);

    // Setup ClickHouse client
    let clickhouse_client = Client::default()
        .with_url("http://localhost:8123")
        .with_database("dhcp");

    // Create analytics channel
    let (analytics_tx, analytics_rx) = mpsc::channel(10_000);

    // Spawn analytics writer
    let writer = analytics::writer::ClickHouseWriter::new(
        clickhouse_client,
        analytics_rx,
        "events_v4",
        "events_v6",
    );
    tokio::spawn(writer.run());

    // Build the service stack
    let dhcp_service = DhcpService::new(
        Arc::clone(&config),
        Arc::clone(&reservations),
        Arc::clone(&leases),
    );

    let service = ServiceBuilder::new()
        .layer(AnalyticsLayer::new(analytics_tx))
        // Could add more layers here:
        // .layer(RateLimitLayer::new(...))
        // .layer(MetricsLayer::new(...))
        .service(dhcp_service);

    // Start transport
    let bind_v4 = std::env::var("BIND_V4").unwrap_or_else(|_| "0.0.0.0:67".into());
    let bind_v6 = std::env::var("BIND_V6").unwrap_or_else(|_| "[::]:547".into());

    info!(
        "Starting DHCP server on {} (v4) and {} (v6)",
        bind_v4, bind_v6
    );

    let transport = transport::UdpTransport::new(&bind_v4, &bind_v6, service).await?;
    transport.run().await;

    Ok(())
}
