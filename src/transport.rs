use std::sync::Arc;

use dhcproto::{v4, v6, Decodable};
use tokio::net::UdpSocket;
use tower::Service;
use tracing::{debug, error, trace, warn};

use crate::{
    service::dhcp::DhcpServiceResponse,
    types::{DhcpPayload, DhcpRequest, RelayInfoV4, V4Request, V6Request},
};

pub struct UdpTransport<S> {
    socket_v4: Arc<UdpSocket>,
    socket_v6: Arc<UdpSocket>,
    service: S,
}

impl<S> UdpTransport<S>
where
    S: Service<DhcpRequest, Response = DhcpServiceResponse> + Clone + Send + 'static,
    S::Error: std::fmt::Display + Send,
    S::Future: Send,
{
    pub async fn new(bind_v4: &str, bind_v6: &str, service: S) -> std::io::Result<Self> {
        let socket_v4 = Arc::new(UdpSocket::bind(bind_v4).await?);
        let socket_v6 = Arc::new(UdpSocket::bind(bind_v6).await?);

        Ok(Self {
            socket_v4,
            socket_v6,
            service,
        })
    }

    pub async fn run(self) {
        let v4_socket = Arc::clone(&self.socket_v4);
        let v6_socket = Arc::clone(&self.socket_v6);
        let service = self.service;

        // Spawn V4 receiver
        let v4_service = service.clone();
        let v4_handle = tokio::spawn(async move {
            run_v4_loop(v4_socket, v4_service).await;
        });

        // Spawn V6 receiver
        let v6_handle = tokio::spawn(async move {
            run_v6_loop(v6_socket, service).await;
        });

        // Wait for both
        let _ = tokio::join!(v4_handle, v6_handle);
    }
}

async fn run_v4_loop<S>(socket: Arc<UdpSocket>, service: S)
where
    S: Service<DhcpRequest, Response = DhcpServiceResponse> + Clone + Send + 'static,
    S::Error: std::fmt::Display + Send,
    S::Future: Send,
{
    let mut buf = vec![0u8; 2048];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                error!("V4 recv error: {}", e);
                continue;
            }
        };

        trace!("V4 received {} bytes from {}", len, src);

        let msg = match v4::Message::from_bytes(&buf[..len]) {
            Ok(m) => m,
            Err(e) => {
                warn!("V4 parse error: {}", e);
                continue;
            }
        };

        let relay_info = extract_relay_info_v4(&msg);
        let request = DhcpRequest {
            source: src,
            received_at: std::time::Instant::now(),
            payload: DhcpPayload::V4(V4Request {
                message: msg,
                relay_info,
            }),
        };

        // Clone service for this request
        let mut svc = service.clone();
        let socket = Arc::clone(&socket);

        // Spawn handler task
        tokio::spawn(async move {
            match svc.call(request).await {
                Ok(response) => {
                    if let Some(resp) = response.response {
                        if let Err(e) = socket.send_to(&resp.payload, resp.destination).await {
                            error!("V4 send error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("V4 handler error: {}", e);
                }
            }
        });
    }
}

async fn run_v6_loop<S>(socket: Arc<UdpSocket>, service: S)
where
    S: Service<DhcpRequest, Response = DhcpServiceResponse> + Clone + Send + 'static,
    S::Error: std::fmt::Display + Send,
    S::Future: Send,
{
    let mut buf = vec![0u8; 2048];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                error!("V6 recv error: {}", e);
                continue;
            }
        };

        trace!("V6 received {} bytes from {}", len, src);

        let relay_msg = match v6::RelayMessage::from_bytes(&buf[..len]) {
            Ok(m) => m,
            Err(e) => {
                warn!("V6 parse error: {}", e);
                continue;
            }
        };

        // Extract inner message
        let inner = match extract_inner_message(&relay_msg) {
            Some(m) => m,
            None => {
                debug!("No inner message in relay");
                continue;
            }
        };

        let client_duid = match inner.opts().iter().find_map(|o| match o {
            v6::DhcpOption::ClientId(id) => Some(id.clone()),
            _ => None,
        }) {
            Some(d) => d,
            None => {
                debug!("No client DUID");
                continue;
            }
        };

        let hw_addr = extract_hw_addr(&relay_msg);

        let request = DhcpRequest {
            source: src,
            received_at: std::time::Instant::now(),
            payload: DhcpPayload::V6(V6Request {
                relay_message: relay_msg.clone(),
                inner_message: inner,
                client_duid,
                hw_addr,
                link_addr: relay_msg.link_addr,
                peer_addr: relay_msg.peer_addr,
            }),
        };

        let mut svc = service.clone();
        let socket = Arc::clone(&socket);

        tokio::spawn(async move {
            match svc.call(request).await {
                Ok(response) => {
                    if let Some(resp) = response.response {
                        if let Err(e) = socket.send_to(&resp.payload, resp.destination).await {
                            error!("V6 send error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("V6 handler error: {}", e);
                }
            }
        });
    }
}

fn extract_relay_info_v4(_msg: &v4::Message) -> Option<RelayInfoV4> {
    // Extract Option 82 etc.
    None // Implementation detail
}

fn extract_inner_message(relay: &v6::RelayMessage) -> Option<v6::Message> {
    relay.opts.iter().find_map(|o| match o {
        v6::DhcpOption::RelayMsg(v6::RelayMessageData::Message(m)) => Some(m.clone()),
        _ => None,
    })
}

fn extract_hw_addr(relay: &v6::RelayMessage) -> Option<advmac::MacAddr6> {
    relay.opts.iter().find_map(|o| match o {
        v6::DhcpOption::ClientLinklayerAddress(ll) if ll.address.len() == 6 => {
            let mut bytes = [0u8; 6];
            bytes.copy_from_slice(&ll.address);
            Some(advmac::MacAddr6::new(bytes))
        }
        _ => None,
    })
}
