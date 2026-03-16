use std::net::IpAddr;
use std::sync::Arc;

use crate::types::Backend;

use super::LoadBalancer;

/// Least-connections load balancer.
///
/// Selects the available backend with the fewest active connections,
/// using `backend.active_count()`.
pub struct LeastConnections;

impl LeastConnections {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LeastConnections {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for LeastConnections {
    fn select<'a>(
        &self,
        backends: &'a [Arc<Backend>],
        _client_ip: Option<IpAddr>,
    ) -> Option<&'a Arc<Backend>> {
        backends
            .iter()
            .filter(|b| b.is_available())
            .min_by_key(|b| b.active_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BackendId, ConnectionGuard};
    use std::sync::atomic::Ordering;

    fn make_backends(n: usize) -> Vec<Arc<Backend>> {
        (0..n)
            .map(|i| {
                Arc::new(Backend::new(
                    BackendId(format!("b{}", i)),
                    format!("127.0.0.1:{}", 8080 + i).parse().unwrap(),
                    1,
                    false,
                ))
            })
            .collect()
    }

    #[test]
    fn test_least_conn_picks_lowest() {
        let backends = make_backends(3);

        // Give b0 two connections, b1 one connection, b2 zero
        let _g0a = ConnectionGuard::new(backends[0].clone());
        let _g0b = ConnectionGuard::new(backends[0].clone());
        let _g1 = ConnectionGuard::new(backends[1].clone());

        let lc = LeastConnections::new();
        let selected = lc.select(&backends, None).unwrap();
        assert_eq!(selected.id.0, "b2");
    }

    #[test]
    fn test_least_conn_skips_unavailable() {
        let backends = make_backends(3);

        // b2 has fewest connections (0) but is unhealthy
        let _g0 = ConnectionGuard::new(backends[0].clone());
        backends[2].healthy.store(false, Ordering::Relaxed);

        let lc = LeastConnections::new();
        let selected = lc.select(&backends, None).unwrap();
        // b1 has 0 active, b0 has 1 active, b2 is unavailable
        assert_eq!(selected.id.0, "b1");
    }

    #[test]
    fn test_least_conn_empty() {
        let backends: Vec<Arc<Backend>> = vec![];
        let lc = LeastConnections::new();
        assert!(lc.select(&backends, None).is_none());
    }

    #[test]
    fn test_least_conn_all_unavailable() {
        let backends = make_backends(2);
        backends[0].enabled.store(false, Ordering::Relaxed);
        backends[1].healthy.store(false, Ordering::Relaxed);

        let lc = LeastConnections::new();
        assert!(lc.select(&backends, None).is_none());
    }

    #[test]
    fn test_least_conn_updates_after_connection_drop() {
        let backends = make_backends(2);

        // b0 gets a connection, b1 has none
        let guard = ConnectionGuard::new(backends[0].clone());
        let lc = LeastConnections::new();

        let selected = lc.select(&backends, None).unwrap();
        assert_eq!(selected.id.0, "b1");

        // Drop the connection on b0
        drop(guard);

        // Now both have 0 connections; first match wins (b0)
        let selected = lc.select(&backends, None).unwrap();
        assert_eq!(selected.id.0, "b0");
    }
}
