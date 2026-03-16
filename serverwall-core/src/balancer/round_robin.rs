use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::types::Backend;

use super::LoadBalancer;

/// Round-robin load balancer.
///
/// Uses an atomic counter to distribute requests evenly across available backends.
/// Unavailable backends are skipped.
pub struct RoundRobin {
    counter: AtomicUsize,
}

impl RoundRobin {
    pub fn new() -> Self {
        Self {
            counter: AtomicUsize::new(0),
        }
    }
}

impl Default for RoundRobin {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for RoundRobin {
    fn select<'a>(
        &self,
        backends: &'a [Arc<Backend>],
        _client_ip: Option<IpAddr>,
    ) -> Option<&'a Arc<Backend>> {
        let available: Vec<usize> = backends
            .iter()
            .enumerate()
            .filter(|(_, b)| b.is_available())
            .map(|(i, _)| i)
            .collect();

        if available.is_empty() {
            return None;
        }

        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % available.len();
        Some(&backends[available[idx]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BackendId;
    use std::collections::HashMap;
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
    fn test_round_robin_distributes_evenly() {
        let backends = make_backends(3);
        let rr = RoundRobin::new();
        let mut counts: HashMap<String, usize> = HashMap::new();

        for _ in 0..300 {
            let selected = rr.select(&backends, None).unwrap();
            *counts.entry(selected.id.0.clone()).or_insert(0) += 1;
        }

        assert_eq!(counts.get("b0"), Some(&100));
        assert_eq!(counts.get("b1"), Some(&100));
        assert_eq!(counts.get("b2"), Some(&100));
    }

    #[test]
    fn test_round_robin_skips_unavailable() {
        let backends = make_backends(3);
        backends[1].healthy.store(false, Ordering::Relaxed);

        let rr = RoundRobin::new();
        let mut counts: HashMap<String, usize> = HashMap::new();

        for _ in 0..100 {
            let selected = rr.select(&backends, None).unwrap();
            *counts.entry(selected.id.0.clone()).or_insert(0) += 1;
        }

        assert_eq!(counts.get("b0"), Some(&50));
        assert!(counts.get("b1").is_none());
        assert_eq!(counts.get("b2"), Some(&50));
    }

    #[test]
    fn test_round_robin_empty() {
        let backends: Vec<Arc<Backend>> = vec![];
        let rr = RoundRobin::new();
        assert!(rr.select(&backends, None).is_none());
    }

    #[test]
    fn test_round_robin_wraps_around() {
        let backends = make_backends(2);
        let rr = RoundRobin::new();

        let first = rr.select(&backends, None).unwrap();
        let second = rr.select(&backends, None).unwrap();
        let third = rr.select(&backends, None).unwrap();

        assert_eq!(first.id.0, "b0");
        assert_eq!(second.id.0, "b1");
        assert_eq!(third.id.0, "b0");
    }
}
