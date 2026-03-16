use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;

use crate::pipeline::{EnvelopeContext, PreDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// A sliding-window entry.
#[derive(Debug, Clone)]
struct WindowEntry {
    timestamps: Vec<Instant>,
}

impl WindowEntry {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    fn record(&mut self, now: Instant, window: Duration) {
        // Prune old entries.
        self.timestamps.retain(|t| now.duration_since(*t) < window);
        self.timestamps.push(now);
    }

    fn count(&self, now: Instant, window: Duration) -> u64 {
        self.timestamps
            .iter()
            .filter(|t| now.duration_since(**t) < window)
            .count() as u64
    }
}

/// Per-IP, per-domain, per-sender sliding window rate limiting.
pub struct SmtpRateLimitCheck {
    pub weight: f64,
    pub max_per_ip: u64,
    pub max_per_domain: u64,
    pub max_per_sender: u64,
    pub window: Duration,
    ip_map: Arc<DashMap<String, WindowEntry>>,
    domain_map: Arc<DashMap<String, WindowEntry>>,
    sender_map: Arc<DashMap<String, WindowEntry>>,
}

impl SmtpRateLimitCheck {
    pub fn new(
        weight: f64,
        max_per_ip: u64,
        max_per_domain: u64,
        max_per_sender: u64,
        window: Duration,
    ) -> Self {
        Self {
            weight,
            max_per_ip,
            max_per_domain,
            max_per_sender,
            window,
            ip_map: Arc::new(DashMap::new()),
            domain_map: Arc::new(DashMap::new()),
            sender_map: Arc::new(DashMap::new()),
        }
    }
}

#[async_trait]
impl PreDataCheck for SmtpRateLimitCheck {
    fn name(&self) -> &str {
        "rate_limit"
    }

    async fn check(&self, ctx: &EnvelopeContext) -> (CheckOutcome, Option<ScoreContribution>) {
        let now = Instant::now();
        let ip_key = ctx.client_ip.to_string();

        // -- Per-IP --
        {
            let mut entry = self.ip_map.entry(ip_key.clone()).or_insert_with(WindowEntry::new);
            entry.record(now, self.window);
            let count = entry.count(now, self.window);
            if count > self.max_per_ip {
                let severity = self.weight * 1.0;
                return (
                    CheckOutcome::Reject {
                        reason: format!(
                            "Rate limit exceeded for IP {} ({}/{})",
                            ctx.client_ip, count, self.max_per_ip,
                        ),
                    },
                    Some(ScoreContribution {
                        check_name: "rate_limit".to_string(),
                        category: CheckCategory::RateLimit,
                        score: severity,
                        description: format!("IP {} rate limit exceeded", ctx.client_ip),
                    }),
                );
            }
        }

        // -- Per-sender --
        if !ctx.mail_from.is_empty() {
            let sender_key = ctx.mail_from.to_lowercase();
            let mut entry = self.sender_map.entry(sender_key.clone()).or_insert_with(WindowEntry::new);
            entry.record(now, self.window);
            let count = entry.count(now, self.window);
            if count > self.max_per_sender {
                let severity = self.weight * 0.8;
                return (
                    CheckOutcome::Hit {
                        severity,
                        detail: format!("Sender rate limit: {} ({}/{})", ctx.mail_from, count, self.max_per_sender),
                    },
                    Some(ScoreContribution {
                        check_name: "rate_limit".to_string(),
                        category: CheckCategory::RateLimit,
                        score: severity,
                        description: format!("Sender {} rate limit", ctx.mail_from),
                    }),
                );
            }
        }

        // -- Per-domain --
        if let Some((_, domain)) = ctx.mail_from.rsplit_once('@') {
            let domain_key = domain.trim_end_matches('>').to_lowercase();
            let mut entry = self.domain_map.entry(domain_key.clone()).or_insert_with(WindowEntry::new);
            entry.record(now, self.window);
            let count = entry.count(now, self.window);
            if count > self.max_per_domain {
                let severity = self.weight * 0.6;
                return (
                    CheckOutcome::Hit {
                        severity,
                        detail: format!("Domain rate limit: {} ({}/{})", domain_key, count, self.max_per_domain),
                    },
                    Some(ScoreContribution {
                        check_name: "rate_limit".to_string(),
                        category: CheckCategory::RateLimit,
                        score: severity,
                        description: format!("Domain {} rate limit", domain_key),
                    }),
                );
            }
        }

        (CheckOutcome::Pass, None)
    }
}
