// src/middleware/analytics.rs

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use clickhouse::Client;
use serde::Serialize;
use tokio::sync::mpsc;
use tower::{Layer, Service};
use tracing::{debug, error};

use crate::service::dhcp::{DhcpError, DhcpServiceResponse};
use crate::types::{DhcpPayload, DhcpRequest, RequestOutcome};

/// ClickHouse row for DHCPv4 events
#[derive(Debug, Clone, Serialize, clickhouse::Row)]
pub struct DhcpEventV4 {
    pub timestamp: u64,
    pub message_type: String,
    pub xid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opt82_circuit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opt82_remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_ipv4: Option<String>,
    pub success: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub latency_us: u64,
}

/// ClickHouse row for DHCPv6 events
#[derive(Debug, Clone, Serialize, clickhouse::Row)]
pub struct DhcpEventV6 {
    pub timestamp: u64,
    pub message_type: String,
    pub xid: String, // hex encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_duid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_ipv6_na: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_ipv6_pd_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_ipv6_pd_len: Option<u8>,
    pub success: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub latency_us: u64,
}

/// Events to be written to ClickHouse
pub enum AnalyticsEvent {
    V4(DhcpEventV4),
    V6(DhcpEventV6),
}

/// Analytics Layer - wraps services to emit events
#[derive(Clone)]
pub struct AnalyticsLayer {
    sender: mpsc::Sender<AnalyticsEvent>,
}

impl AnalyticsLayer {
    pub fn new(sender: mpsc::Sender<AnalyticsEvent>) -> Self {
        Self { sender }
    }
}

impl<S> Layer<S> for AnalyticsLayer {
    type Service = AnalyticsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AnalyticsService {
            inner,
            sender: self.sender.clone(),
        }
    }
}

/// Analytics Service - wraps inner service and emits events
#[derive(Clone)]
pub struct AnalyticsService<S> {
    inner: S,
    sender: mpsc::Sender<AnalyticsEvent>,
}

impl<S> Service<DhcpRequest> for AnalyticsService<S>
where
    S: Service<DhcpRequest, Response = DhcpServiceResponse, Error = DhcpError>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    type Response = DhcpServiceResponse;
    type Error = DhcpError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: DhcpRequest) -> Self::Future {
        let mut inner = self.inner.clone();
        let sender = self.sender.clone();
        let start = Instant::now();

        // Capture request metadata before moving
        let request_meta = extract_request_meta(&req);

        Box::pin(async move {
            let result = inner.call(req).await;
            let latency = start.elapsed();

            // Build and send analytics event
            match &result {
                Ok(response) => {
                    let event = build_event(request_meta, &response.outcome, latency);
                    if sender.send(event).await.is_err() {
                        debug!("Analytics channel closed");
                    }
                }
                Err(e) => {
                    debug!("Request failed with error: {}", e);
                }
            }

            result
        })
    }
}

#[derive(Clone)]
struct RequestMeta {
    payload_type: PayloadType,
    mac_address: Option<String>,
    client_duid: Option<String>,
    xid_v4: Option<u32>,
    xid_v6: Option<[u8; 3]>,
    opt82_circuit: Option<String>,
    opt82_remote: Option<String>,
}

#[derive(Clone, Copy)]
enum PayloadType {
    V4,
    V6,
}

fn extract_request_meta(req: &DhcpRequest) -> RequestMeta {
    match &req.payload {
        DhcpPayload::V4(v4) => RequestMeta {
            payload_type: PayloadType::V4,
            mac_address: advmac::MacAddr6::try_from(v4.message.chaddr())
                .ok()
                .map(|m| m.to_string()),
            client_duid: None,
            xid_v4: Some(v4.message.xid()),
            xid_v6: None,
            opt82_circuit: v4.relay_info.as_ref().and_then(|r| r.circuit_id.clone()),
            opt82_remote: v4.relay_info.as_ref().and_then(|r| r.remote_id.clone()),
        },
        DhcpPayload::V6(v6) => RequestMeta {
            payload_type: PayloadType::V6,
            mac_address: v6.hw_addr.map(|m| m.to_string()),
            client_duid: todo!(),
            xid_v4: None,
            xid_v6: Some(v6.inner_message.xid()),
            opt82_circuit: None,
            opt82_remote: None,
        },
    }
}

fn build_event(
    meta: RequestMeta,
    outcome: &RequestOutcome,
    latency: std::time::Duration,
) -> AnalyticsEvent {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    match meta.payload_type {
        PayloadType::V4 => AnalyticsEvent::V4(DhcpEventV4 {
            timestamp,
            message_type: outcome.message_type.unwrap_or("unknown").to_string(),
            xid: meta.xid_v4.unwrap_or(0),
            mac_address: meta.mac_address,
            opt82_circuit: meta.opt82_circuit,
            opt82_remote: meta.opt82_remote,
            requested_ipv4: None, // Could extract from outcome
            assigned_ipv4: outcome.assigned_v4.map(|ip| ip.to_string()),
            success: if outcome.success { 1 } else { 0 },
            failure_reason: outcome.failure_reason.map(String::from),
            latency_us: latency.as_micros() as u64,
        }),
        PayloadType::V6 => {
            let xid = meta.xid_v6.unwrap_or([0, 0, 0]);
            AnalyticsEvent::V6(DhcpEventV6 {
                timestamp,
                message_type: outcome.message_type.unwrap_or("unknown").to_string(),
                xid: format!("{:02x}{:02x}{:02x}", xid[0], xid[1], xid[2]),
                mac_address: meta.mac_address,
                client_duid: meta.client_duid,
                assigned_ipv6_na: outcome.assigned_v6_na.map(|ip| ip.to_string()),
                assigned_ipv6_pd_addr: outcome.assigned_v6_pd.map(|net| net.addr().to_string()),
                assigned_ipv6_pd_len: outcome.assigned_v6_pd.map(|net| net.prefix_len()),
                success: if outcome.success { 1 } else { 0 },
                failure_reason: outcome.failure_reason.map(String::from),
                latency_us: latency.as_micros() as u64,
            })
        }
    }
}
