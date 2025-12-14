use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tower::Service;

use crate::config::Config;
use crate::leasedb::LeaseDb;
use crate::reservationdb::ReservationDb;
use crate::service::v6_handlers;
use crate::types::{DhcpPayload, DhcpRequest, DhcpResponse, RequestOutcome};

/// Core DHCP service - handles requests and produces responses
#[derive(Clone)]
pub struct DhcpService {
    config: Arc<Config>,
    reservations: Arc<ReservationDb>,
    leases: Arc<LeaseDb>,
}

impl DhcpService {
    pub fn new(
        config: Arc<Config>,
        reservations: Arc<ReservationDb>,
        leases: Arc<LeaseDb>,
    ) -> Self {
        Self {
            config,
            reservations,
            leases,
        }
    }
}

/// Response type includes outcome for analytics middleware
pub struct DhcpServiceResponse {
    pub response: Option<DhcpResponse>,
    pub outcome: RequestOutcome,
}

#[derive(Debug)]
pub enum DhcpError {
    Parse(String),
    Internal(String),
}

impl fmt::Display for DhcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpError::Internal(e) => write!(f, "Internal error {e}"),
            DhcpError::Parse(e) => write!(f, "Parse error {e}"),
        }
    }
}

impl Service<DhcpRequest> for DhcpService {
    type Response = DhcpServiceResponse;
    type Error = DhcpError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Always ready - no backpressure from this service
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: DhcpRequest) -> Self::Future {
        // Clone what we need for the async block
        let config = Arc::clone(&self.config);
        let reservations = Arc::clone(&self.reservations);
        let leases = Arc::clone(&self.leases);

        Box::pin(async move {
            match req.payload {
                DhcpPayload::V4(_v4_req) => {
                    todo!()
                    //v4_handlers::handle_v4(&config, &reservations, &leases, v4_req, req.source)
                }
                DhcpPayload::V6(v6_req) => {
                    v6_handlers::handle_v6(&config, &reservations, &leases, v6_req, req.source)
                }
            }
        })
    }
}
