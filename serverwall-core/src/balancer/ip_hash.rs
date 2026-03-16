use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;

use crate::types::Backend;

use super::LoadBalancer;

/// IP-hash load balancer.
///
/// Routes clients to a consistent backend based on their IP address.
/// If `client_ip` is not provided, falls back to localhost.
pub struct IpHash;

impl IpHash {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IpHash {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for IpHash {
    fn select<'a>(
        &self,
        backends: &'a [Arc<Backend>],
        client_ip: Option<IpAddr>,
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

        let ip = client_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % available.len();
        Some(&backends[available[idx]])
    }
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
    fn test_ip_hash_consistent_for_same_ip() {
        let backends = make_backends(5);
        let ih = IpHash::new();
        let ip: IpAddr = "10.0.0.42".parse().unwrap();

        let first = ih.select(&backends, Some(ip)).unwrap();
        for _ in 0..100 {
            let selected = ih.select(&backends, Some(ip)).unwrap();
            assert_eq!(selected.id.0, first.id.0);
        }
    }

    #[test]
    fn test_ip_hash_different_ips_can_differ() {
        let backends = make_backends(10);
        let ih = IpHash::new();

        // With enough backends and different IPs, at least some should differ
        let mut seen = std::collections::HashSet::new();
        for i in 1..=50u8 {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            let selected = ih.select(&backends, Some(ip)).unwrap();
            seen.insert(selected.id.0.clone());
        }
        // With 50 different IPs and 10 backends, we should see more than 1 backend
        assert!(seen.len() > 1);
    }

    #[test]
    fn test_ip_hash_skips_unavailable() {
        let backends = make_backends(3);
        let ih = IpHash::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Get the initial selection
        let initial = ih.select(&backends, Some(ip)).unwrap().id.0.clone();

        // Mark all backends as unavailable except one
        for b in &backends {
            b.healthy.store(false, Ordering::Relaxed);
        }
        backends[2].healthy.store(true, Ordering::Relaxed);

        let selected = ih.select(&backends, Some(ip)).unwrap();
        assert_eq!(selected.id.0, "b2");

        // Restore all
        for b in &backends {
            b.healthy.store(true, Ordering::Relaxed);
        }
        // Should go back to original
        let restored = ih.select(&backends, Some(ip)).unwrap();
        assert_eq!(restored.id.0, initial);
    }

    #[test]
    fn test_ip_hash_empty() {
        let backends: Vec<Arc<Backend>> = vec![];
        let ih = IpHash::new();
        assert!(ih.select(&backends, Some("1.2.3.4".parse().unwrap())).is_none());
    }

    #[test]
    fn test_ip_hash_fallback_without_client_ip() {
        let backends = make_backends(3);
        let ih = IpHash::new();

        // Should not panic with None client_ip
        let selected = ih.select(&backends, None);
        assert!(selected.is_some());

        // Should be consistent
        let first = ih.select(&backends, None).unwrap().id.0.clone();
        let second = ih.select(&backends, None).unwrap().id.0.clone();
        assert_eq!(first, second);
    }
}
