use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use regex::Regex;

use crate::pipeline::{EnvelopeContext, PreDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Verifies that the connecting IP has a valid reverse DNS (PTR) record
/// and performs Forward-Confirmed reverse DNS (FCrDNS) validation.
pub struct ReverseDnsCheck {
    pub weight: f64,
    resolver: Arc<TokioAsyncResolver>,
    generic_ptr_re: Regex,
}

impl ReverseDnsCheck {
    pub fn new(weight: f64) -> Self {
        let resolver = Arc::new(
            TokioAsyncResolver::tokio_from_system_conf()
                .unwrap_or_else(|_| TokioAsyncResolver::tokio(
                    hickory_resolver::config::ResolverConfig::default(),
                    hickory_resolver::config::ResolverOpts::default(),
                )),
        );
        // Matches generic PTR records like "12-34-56-78.isp.com" or
        // "ip-10-0-0-1.pool.example.net"
        let generic_ptr_re = Regex::new(
            r"(?i)^(ip|host|pool|dynamic|dhcp|dsl|cable|ppp|dial|broadband|unknown|unresolved|static|client|customer|user|adsl|mob|gprs)[\-\.]?\d"
        ).unwrap();

        Self {
            weight,
            resolver,
            generic_ptr_re,
        }
    }
}

#[async_trait]
impl PreDataCheck for ReverseDnsCheck {
    fn name(&self) -> &str {
        "rdns"
    }

    async fn check(&self, ctx: &EnvelopeContext) -> (CheckOutcome, Option<ScoreContribution>) {
        let ip = ctx.client_ip;

        // Step 1: PTR lookup
        let ptr_names = match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                let names: Vec<String> = lookup
                    .iter()
                    .map(|name| name.to_string().trim_end_matches('.').to_string())
                    .collect();
                if names.is_empty() {
                    return no_ptr(self.weight, ip);
                }
                names
            }
            Err(_) => {
                return no_ptr(self.weight, ip);
            }
        };

        // Step 2: FCrDNS -- forward-resolve each PTR name and confirm the IP
        let mut fcrdns_ok = false;
        let mut hostname = ptr_names[0].clone();

        for ptr_name in &ptr_names {
            if let Ok(addrs) = self.resolver.lookup_ip(ptr_name).await {
                for addr in addrs.iter() {
                    if addr == ip {
                        fcrdns_ok = true;
                        hostname = ptr_name.clone();
                        break;
                    }
                }
            }
            if fcrdns_ok {
                break;
            }
        }

        if !fcrdns_ok {
            let score = self.weight * 0.7;
            return (
                CheckOutcome::Hit {
                    severity: score,
                    detail: format!("FCrDNS mismatch for {} (PTR: {})", ip, hostname),
                },
                Some(ScoreContribution {
                    check_name: "rdns".to_string(),
                    category: CheckCategory::Reputation,
                    score,
                    description: format!("FCrDNS mismatch for {}", ip),
                }),
            );
        }

        // Step 3: Check for generic PTR patterns
        if self.generic_ptr_re.is_match(&hostname) {
            let score = self.weight * 0.4;
            return (
                CheckOutcome::Hit {
                    severity: score,
                    detail: format!("Generic PTR record: {}", hostname),
                },
                Some(ScoreContribution {
                    check_name: "rdns".to_string(),
                    category: CheckCategory::Reputation,
                    score,
                    description: format!("Generic PTR: {}", hostname),
                }),
            );
        }

        (CheckOutcome::Pass, None)
    }
}

fn no_ptr(weight: f64, ip: IpAddr) -> (CheckOutcome, Option<ScoreContribution>) {
    let score = weight * 1.0;
    (
        CheckOutcome::Hit {
            severity: score,
            detail: format!("No PTR record for {}", ip),
        },
        Some(ScoreContribution {
            check_name: "rdns".to_string(),
            category: CheckCategory::Reputation,
            score,
            description: format!("No PTR record for {}", ip),
        }),
    )
}
