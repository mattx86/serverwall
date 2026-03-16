use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

// =============================================================================
// Identifiers (newtype wrappers)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FrontendId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BackendId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VipAddr(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PoolId(pub String);

impl fmt::Display for FrontendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for VipAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for PoolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for FrontendId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<&str> for BackendId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<&str> for PoolId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

// =============================================================================
// Backend runtime state
// =============================================================================

/// A backend server target with runtime state, used by load balancers.
#[derive(Debug)]
pub struct Backend {
    pub id: BackendId,
    /// Opaque 6-character hex tag derived from UUID v5 of "{id}@{addr}".
    /// Used in session cookies and SMTP Received headers without exposing
    /// the backend address or identity.
    pub tag: String,
    pub address: SocketAddr,
    pub weight: u32,
    pub tls: bool,
    pub tls_verify: bool,
    pub tls_sni: Option<String>,
    pub max_connections: Option<usize>,
    pub enabled: AtomicBool,
    pub active_connections: AtomicUsize,
    pub total_connections: AtomicUsize,
    pub healthy: AtomicBool,
}

impl Backend {
    pub fn new(id: BackendId, address: SocketAddr, weight: u32, tls: bool) -> Self {
        let tag_input = format!("{}@{}", id, address);
        let tag_uuid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, tag_input.as_bytes());
        let bytes = tag_uuid.as_bytes();
        let tag = format!("{:02x}{:02x}{:02x}", bytes[0], bytes[1], bytes[2]);
        Self {
            id,
            tag,
            address,
            weight,
            tls,
            tls_verify: false,
            tls_sni: None,
            max_connections: None,
            enabled: AtomicBool::new(true),
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicUsize::new(0),
            healthy: AtomicBool::new(true),
        }
    }

    pub fn is_available(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
            && self.healthy.load(Ordering::Relaxed)
            && self
                .max_connections
                .map(|max| self.active_connections.load(Ordering::Relaxed) < max)
                .unwrap_or(true)
    }

    pub fn active_count(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }
}

/// Guard that decrements active connections when dropped.
pub struct ConnectionGuard {
    backend: Arc<Backend>,
}

impl ConnectionGuard {
    pub fn new(backend: Arc<Backend>) -> Self {
        backend.active_connections.fetch_add(1, Ordering::Relaxed);
        backend.total_connections.fetch_add(1, Ordering::Relaxed);
        Self { backend }
    }

    pub fn backend(&self) -> &Backend {
        &self.backend
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.backend
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

// =============================================================================
// Connection info
// =============================================================================

/// Information about an incoming client connection.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub local_addr: SocketAddr,
    pub frontend_name: String,
    pub tls_sni: Option<String>,
    pub request_id: String,
}

impl ConnectionInfo {
    pub fn client_addr(&self) -> SocketAddr {
        SocketAddr::new(self.client_ip, self.client_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_availability() {
        let backend = Arc::new(Backend::new(
            BackendId::from("test"),
            "127.0.0.1:8080".parse().unwrap(),
            1,
            false,
        ));
        assert!(backend.is_available());

        backend.enabled.store(false, Ordering::Relaxed);
        assert!(!backend.is_available());
        backend.enabled.store(true, Ordering::Relaxed);

        backend.healthy.store(false, Ordering::Relaxed);
        assert!(!backend.is_available());
    }

    #[test]
    fn test_connection_guard() {
        let backend = Arc::new(Backend::new(
            BackendId::from("test"),
            "127.0.0.1:8080".parse().unwrap(),
            1,
            false,
        ));
        assert_eq!(backend.active_count(), 0);

        {
            let _guard = ConnectionGuard::new(backend.clone());
            assert_eq!(backend.active_count(), 1);

            let _guard2 = ConnectionGuard::new(backend.clone());
            assert_eq!(backend.active_count(), 2);
        }

        assert_eq!(backend.active_count(), 0);
        assert_eq!(backend.total_connections.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_max_connections_limit() {
        let mut backend = Backend::new(
            BackendId::from("test"),
            "127.0.0.1:8080".parse().unwrap(),
            1,
            false,
        );
        backend.max_connections = Some(1);
        let backend = Arc::new(backend);

        assert!(backend.is_available());
        let _guard = ConnectionGuard::new(backend.clone());
        assert!(!backend.is_available());
    }
}
