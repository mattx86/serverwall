use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Per-sender-domain hourly message rate limiter.
pub struct OutboundRateLimit {
    max_per_hour: u64,
    /// domain -> list of send timestamps
    counters: Mutex<HashMap<String, Vec<Instant>>>,
}

impl OutboundRateLimit {
    /// Create a rate limiter with the given per-domain hourly limit.
    pub fn new(max_per_hour: u64) -> Self {
        Self {
            max_per_hour,
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether a message from `sender_domain` is within limits.
    /// Returns `Ok(())` if allowed, `Err(message)` if rate exceeded.
    pub fn check(&self, sender_domain: &str) -> Result<(), String> {
        let mut map = self.counters.lock().unwrap();
        let now = Instant::now();
        let one_hour_ago = now - std::time::Duration::from_secs(3600);

        let entries = map.entry(sender_domain.to_lowercase()).or_default();

        // Purge old entries
        entries.retain(|&ts| ts > one_hour_ago);

        if entries.len() as u64 >= self.max_per_hour {
            return Err(format!(
                "rate limit exceeded for domain {sender_domain}: {}/{} per hour",
                entries.len(),
                self.max_per_hour
            ));
        }

        // Record this send
        entries.push(now);
        Ok(())
    }
}
