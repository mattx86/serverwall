use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use regex::Regex;

use crate::pipeline::{EnvelopeContext, PreDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Validates the HELO/EHLO hostname provided by the connecting client.
pub struct HeloCheck {
    pub weight: f64,
    resolver: Arc<TokioAsyncResolver>,
    hostname_re: Regex,
}

impl HeloCheck {
    pub fn new(weight: f64) -> Self {
        let resolver = Arc::new(
            TokioAsyncResolver::tokio_from_system_conf()
                .unwrap_or_else(|_| TokioAsyncResolver::tokio(
                    hickory_resolver::config::ResolverConfig::default(),
                    hickory_resolver::config::ResolverOpts::default(),
                )),
        );
        // Valid hostname: labels separated by dots, alphanumeric + hyphens.
        let hostname_re = Regex::new(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
        ).unwrap();

        Self {
            weight,
            resolver,
            hostname_re,
        }
    }

    fn is_ip_literal(helo: &str) -> bool {
        // [1.2.3.4] or bare IP
        let stripped = helo.trim_start_matches('[').trim_end_matches(']');
        stripped.parse::<IpAddr>().is_ok()
    }
}

#[async_trait]
impl PreDataCheck for HeloCheck {
    fn name(&self) -> &str {
        "helo"
    }

    async fn check(&self, ctx: &EnvelopeContext) -> (CheckOutcome, Option<ScoreContribution>) {
        let helo = ctx.helo_domain.trim();

        if helo.is_empty() {
            let score = self.weight * 1.0;
            return (
                CheckOutcome::Hit {
                    severity: score,
                    detail: "Empty HELO/EHLO hostname".to_string(),
                },
                Some(ScoreContribution {
                    check_name: "helo".to_string(),
                    category: CheckCategory::Behavioral,
                    score,
                    description: "Empty HELO hostname".to_string(),
                }),
            );
        }

        // IP literal HELO -- mild penalty.
        if Self::is_ip_literal(helo) {
            let score = self.weight * 0.3;
            return (
                CheckOutcome::Hit {
                    severity: score,
                    detail: format!("HELO is an IP literal: {}", helo),
                },
                Some(ScoreContribution {
                    check_name: "helo".to_string(),
                    category: CheckCategory::Behavioral,
                    score,
                    description: format!("HELO IP literal: {}", helo),
                }),
            );
        }

        // Invalid hostname format.
        if !self.hostname_re.is_match(helo) {
            let score = self.weight * 0.8;
            return (
                CheckOutcome::Hit {
                    severity: score,
                    detail: format!("Invalid HELO hostname format: {}", helo),
                },
                Some(ScoreContribution {
                    check_name: "helo".to_string(),
                    category: CheckCategory::Behavioral,
                    score,
                    description: format!("Invalid HELO hostname: {}", helo),
                }),
            );
        }

        // No TLD (single label hostname).
        if !helo.contains('.') {
            let score = self.weight * 0.5;
            return (
                CheckOutcome::Hit {
                    severity: score,
                    detail: format!("HELO hostname has no TLD: {}", helo),
                },
                Some(ScoreContribution {
                    check_name: "helo".to_string(),
                    category: CheckCategory::Behavioral,
                    score,
                    description: format!("HELO no TLD: {}", helo),
                }),
            );
        }

        // Check whether HELO hostname resolves and matches PTR.
        if let Ok(ptr_lookup) = self.resolver.reverse_lookup(ctx.client_ip).await {
            let ptr_names: Vec<String> = ptr_lookup
                .iter()
                .map(|n| n.to_string().trim_end_matches('.').to_lowercase())
                .collect();
            let helo_lower = helo.to_lowercase();
            if !ptr_names.iter().any(|p| *p == helo_lower) {
                let score = self.weight * 0.2;
                return (
                    CheckOutcome::Hit {
                        severity: score,
                        detail: format!("HELO {} does not match PTR", helo),
                    },
                    Some(ScoreContribution {
                        check_name: "helo".to_string(),
                        category: CheckCategory::Behavioral,
                        score,
                        description: format!("HELO/PTR mismatch: {}", helo),
                    }),
                );
            }
        }

        (CheckOutcome::Pass, None)
    }
}
