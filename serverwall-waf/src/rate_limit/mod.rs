use std::net::IpAddr;
use std::time::Instant;

use dashmap::DashMap;

/// Defines a rate limiting rule.
#[derive(Debug, Clone)]
pub struct RateLimitRule {
    pub max_requests: u64,
    pub window_secs: u64,
    pub key: String,
}

/// Determines how to extract the rate limit key.
#[derive(Debug, Clone)]
pub enum RateLimitKey {
    /// Rate limit by client IP address.
    ClientIp,
    /// Rate limit by a specific header value.
    Header(String),
}

impl RateLimitKey {
    pub fn from_str(s: &str) -> Self {
        if s == "client_ip" {
            RateLimitKey::ClientIp
        } else if let Some(header) = s.strip_prefix("header:") {
            RateLimitKey::Header(header.to_string())
        } else {
            RateLimitKey::ClientIp
        }
    }
}

/// A token bucket for rate limiting a single key.
pub struct TokenBucket {
    pub tokens: f64,
    pub max_tokens: f64,
    pub refill_rate: f64,
    pub last_refill: Instant,
}

impl TokenBucket {
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time, then try to consume one.
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
            self.last_refill = now;
        }
    }
}

/// Rate limiter that tracks request rates per key (e.g., IP address).
///
/// Uses `DashMap` for lock-free concurrent access.
pub struct RateLimiter {
    buckets: DashMap<String, TokenBucket>,
    max_requests: f64,
    refill_rate: f64,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// * `max_requests` - Maximum burst size (bucket capacity).
    /// * `window_secs` - Time window in seconds over which `max_requests` are allowed.
    pub fn new() -> Self {
        // Default: 100 requests per 60 seconds
        Self::with_limits(100, 60)
    }

    pub fn with_limits(max_requests: u64, window_secs: u64) -> Self {
        let max = max_requests as f64;
        let refill = if window_secs > 0 {
            max / window_secs as f64
        } else {
            max
        };
        Self {
            buckets: DashMap::new(),
            max_requests: max,
            refill_rate: refill,
        }
    }

    /// Check if a request from the given IP address is allowed.
    pub fn is_allowed(&self, addr: IpAddr) -> bool {
        self.check_key(&addr.to_string())
    }

    /// Check if a request with the given key is allowed.
    pub fn check_key(&self, key: &str) -> bool {
        let mut entry = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.max_requests, self.refill_rate));
        entry.try_consume()
    }

    /// Remove expired/stale entries to prevent unbounded memory growth.
    /// Entries that have been fully refilled (at max tokens) for a long time
    /// can be safely removed.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            let idle = now.duration_since(bucket.last_refill).as_secs();
            // Keep entries that have been active within the last 5 minutes
            idle < 300
        });
    }
}
