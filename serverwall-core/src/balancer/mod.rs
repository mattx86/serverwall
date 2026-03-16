pub mod round_robin;
pub mod least_conn;
pub mod ip_hash;

pub use round_robin::RoundRobin;
pub use least_conn::LeastConnections;
pub use ip_hash::IpHash;

use std::net::IpAddr;
use std::sync::Arc;

use crate::types::Backend;

/// Trait for load-balancing algorithms.
///
/// Implementations must filter backends to only those that are available
/// (via `backend.is_available()`).
pub trait LoadBalancer: Send + Sync {
    /// Select the next backend from the pool.
    ///
    /// `client_ip` is provided for algorithms that need it (e.g., IP hash).
    /// Implementations should only consider backends where `is_available()` is true.
    fn select<'a>(
        &self,
        backends: &'a [Arc<Backend>],
        client_ip: Option<IpAddr>,
    ) -> Option<&'a Arc<Backend>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BackendId;
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
    fn test_select_skips_unavailable() {
        let backends = make_backends(3);
        backends[0].healthy.store(false, Ordering::Relaxed);

        let rr = RoundRobin::new();
        // All selections should skip backend 0
        for _ in 0..10 {
            let selected = rr.select(&backends, None).unwrap();
            assert_ne!(selected.id.0, "b0");
        }
    }

    #[test]
    fn test_select_returns_none_when_all_unavailable() {
        let backends = make_backends(2);
        backends[0].healthy.store(false, Ordering::Relaxed);
        backends[1].enabled.store(false, Ordering::Relaxed);

        let rr = RoundRobin::new();
        assert!(rr.select(&backends, None).is_none());
    }
}
