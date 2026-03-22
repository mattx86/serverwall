use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use serverwall_core::acl::{AclDecision, AccessControlEngine, GeoEngine};
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
    global_ip_acl: Option<Arc<AccessControlEngine>>,
    geo: Option<Arc<GeoEngine>>,
    balancer: Box<dyn LoadBalancer>,
    backends: Vec<Arc<Backend>>,
    /// Global fallback: whether to verify backend TLS certificates.
    backend_tls_verify: bool,
    /// Optional custom CA bundle path for backend TLS verification.
    backend_ca_bundle: Option<PathBuf>,
}

impl RequestPipeline {
    /// Create a new request pipeline.
    pub fn new(
        acl: AccessControlEngine,
        global_ip_acl: Option<Arc<AccessControlEngine>>,
        geo: Option<Arc<GeoEngine>>,
        balancer: Box<dyn LoadBalancer>,
        backends: Vec<Arc<Backend>>,
        backend_tls_verify: bool,
        backend_ca_bundle: Option<PathBuf>,
    ) -> Self {
        Self {
            acl,
            global_ip_acl,
            geo,
            balancer,
            backends,
            backend_tls_verify,
            backend_ca_bundle,
        }
    }

    /// Check the ACL (global IP, per-frontend IP, geo) for a client IP.
    ///
    /// Evaluation order: global IP ACL → per-frontend IP ACL → geo.
    /// Returns `Ok(())` if the client is allowed, or an error if denied.
    pub fn check_acl(&self, client_ip: IpAddr) -> Result<(), ServerWallError> {
        // Global IP ACL (security.acl.ip) is checked first.
        if let Some(ref global) = self.global_ip_acl {
            match global.evaluate(client_ip) {
                AclDecision::Deny => return Err(ServerWallError::AccessDenied { ip: client_ip }),
                AclDecision::Allow => {}
            }
        }
        // Per-frontend ACL.
        match self.acl.evaluate(client_ip) {
            AclDecision::Deny => return Err(ServerWallError::AccessDenied { ip: client_ip }),
            AclDecision::Allow => {}
        }
        if let Some(ref geo) = self.geo {
            if geo.check(client_ip) == AclDecision::Deny {
                return Err(ServerWallError::AccessDenied { ip: client_ip });
            }
        }
        Ok(())
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
    /// Uses the backend's `tls_verify` setting (falling back to the global
    /// `backend_tls_verify` flag) and `backend_ca_bundle` for certificate
    /// verification.
    pub async fn connect_backend_tls(
        &self,
        backend: &Backend,
    ) -> Result<TlsStream<TcpStream>, ServerWallError> {
        let verify = if backend.tls_verify { true } else { self.backend_tls_verify };
        let connector = build_tls_connector(verify, self.backend_ca_bundle.as_deref())?;

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

    /// Returns true if the client IP is explicitly allowed by the global IP ACL.
    ///
    /// Used to implement `acl_bypass_waf`: IPs in the global allow list can
    /// bypass WAF inspection when the feature is enabled in config.
    pub fn is_globally_allowed(&self, ip: IpAddr) -> bool {
        if let Some(ref global) = self.global_ip_acl {
            global.evaluate(ip) == AclDecision::Allow
        } else {
            false
        }
    }

    /// Find a backend by its opaque tag (used for sticky-session routing).
    ///
    /// Returns `None` if no available backend has the given tag.
    pub fn find_backend_by_tag(&self, tag: &str) -> Option<Arc<Backend>> {
        self.backends.iter().find(|b| {
            b.tag == tag && b.enabled.load(std::sync::atomic::Ordering::Relaxed) && b.healthy.load(std::sync::atomic::Ordering::Relaxed)
        }).cloned()
    }

}

