use std::net::IpAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use serverwall_core::acl::{AclDecision, AccessControlEngine};
use serverwall_core::balancer::LoadBalancer;
use serverwall_core::error::ServerWallError;
use serverwall_core::tls::build_tls_connector;
use serverwall_core::types::{Backend, ConnectionGuard};

/// Request pipeline that ties ACL checking, backend selection, and
/// backend connection establishment together.
///
/// Used by protocol-specific proxies to go from "accepted client connection"
/// to "connected backend stream".
pub struct RequestPipeline {
    acl: AccessControlEngine,
    balancer: Box<dyn LoadBalancer>,
    backends: Vec<Arc<Backend>>,
}

impl RequestPipeline {
    /// Create a new request pipeline.
    pub fn new(
        acl: AccessControlEngine,
        balancer: Box<dyn LoadBalancer>,
        backends: Vec<Arc<Backend>>,
    ) -> Self {
        Self {
            acl,
            balancer,
            backends,
        }
    }

    /// Check the ACL for a client IP.
    ///
    /// Returns `Ok(())` if the client is allowed, or an error if denied.
    pub fn check_acl(&self, client_ip: IpAddr) -> Result<(), ServerWallError> {
        match self.acl.evaluate(client_ip) {
            AclDecision::Allow => Ok(()),
            AclDecision::Deny => Err(ServerWallError::AccessDenied { ip: client_ip }),
        }
    }

    /// Select a backend using the configured load balancer.
    ///
    /// Returns a clone of the `Arc<Backend>` and wraps it in a
    /// `ConnectionGuard` that automatically tracks active connections.
    pub fn select_backend(
        &self,
        client_ip: IpAddr,
    ) -> Result<(Arc<Backend>, ConnectionGuard), ServerWallError> {
        let backend = self
            .balancer
            .select(&self.backends, Some(client_ip))
            .ok_or_else(|| {
                ServerWallError::NoHealthyBackends(
                    serverwall_core::types::PoolId("unknown".to_string()),
                )
            })?;

        let backend = Arc::clone(backend);
        let guard = ConnectionGuard::new(backend.clone());
        Ok((backend, guard))
    }

    /// Establish a plain TCP connection to the selected backend.
    pub async fn connect_backend(backend: &Backend) -> Result<TcpStream, ServerWallError> {
        let stream = TcpStream::connect(backend.address).await?;
        Ok(stream)
    }

    /// Establish a TLS connection to the selected backend.
    ///
    /// Uses the backend's `tls_verify` and `tls_sni` settings to configure
    /// the TLS connector.
    pub async fn connect_backend_tls(
        backend: &Backend,
    ) -> Result<TlsStream<TcpStream>, ServerWallError> {
        let connector = build_tls_connector(backend.tls_verify)?;

        let tcp_stream = TcpStream::connect(backend.address).await?;

        // Determine the SNI server name
        let sni = backend.tls_sni.as_deref().unwrap_or("");

        let server_name: ServerName<'static> = if sni.is_empty() {
            ServerName::IpAddress(backend.address.ip().into())
        } else {
            ServerName::try_from(sni.to_string())
                .map_err(|e| ServerWallError::Tls(format!("invalid SNI name '{}': {}", sni, e)))?
        };

        let tls_stream = connector.connect(server_name, tcp_stream).await.map_err(|e| {
            ServerWallError::Tls(format!(
                "TLS handshake to backend {} failed: {}",
                backend.address, e
            ))
        })?;

        Ok(tls_stream)
    }

    /// Find a backend by its opaque tag (used for sticky-session routing).
    ///
    /// Returns `None` if no available backend has the given tag.
    pub fn find_backend_by_tag(&self, tag: &str) -> Option<Arc<Backend>> {
        self.backends.iter().find(|b| {
            b.tag == tag && b.enabled.load(std::sync::atomic::Ordering::Relaxed) && b.healthy.load(std::sync::atomic::Ordering::Relaxed)
        }).cloned()
    }

    /// Returns a reference to the backends.
    pub fn backends(&self) -> &[Arc<Backend>] {
        &self.backends
    }
}
