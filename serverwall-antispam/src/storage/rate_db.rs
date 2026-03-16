use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Persistent storage for rate-limiting counters and sender reputation data.
pub struct RateDb {
    counters: Arc<DashMap<String, Vec<Instant>>>,
    window: Duration,
}

impl RateDb {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(DashMap::new()),
            window: Duration::from_secs(3600),
        }
    }

    pub fn with_window(window: Duration) -> Self {
        Self {
            counters: Arc::new(DashMap::new()),
            window,
        }
    }

    pub fn increment(&self, key: &str) -> u64 {
        let now = Instant::now();
        let mut entry = self.counters.entry(key.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);
        entry.push(now);
        entry.len() as u64
    }

    pub fn get_count(&self, key: &str) -> u64 {
        let now = Instant::now();
        if let Some(entry) = self.counters.get(key) {
            entry.iter().filter(|t| now.duration_since(**t) < self.window).count() as u64
        } else {
            0
        }
    }

    pub fn record_connection(&self, addr: IpAddr) {
        let key = format!("conn:{}", addr);
        self.increment(&key);
    }
}

impl Default for RateDb {
    fn default() -> Self {
        Self::new()
    }
}
