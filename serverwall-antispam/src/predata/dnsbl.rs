use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;

use crate::pipeline::{EnvelopeContext, PreDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Configuration for a single DNSBL zone.
#[derive(Debug, Clone)]
pub struct DnsblZone {
    pub zone: String,
    pub weight_multiplier: f64,
    pub reject_on_hit: bool,
}

/// Checks the connecting IP against DNS-based blocklists.
pub struct DnsblCheck {
    pub zones: Vec<DnsblZone>,
    pub weight: f64,
    resolver: Arc<TokioAsyncResolver>,
}

impl DnsblCheck {
    pub fn new(zones: Vec<DnsblZone>, weight: f64) -> Self {
        let resolver = Arc::new(
            TokioAsyncResolver::tokio_from_system_conf()
                .unwrap_or_else(|_| TokioAsyncResolver::tokio(
                    hickory_resolver::config::ResolverConfig::default(),
                    hickory_resolver::config::ResolverOpts::default(),
                )),
        );
        Self {
            zones,
            weight,
            resolver,
        }
    }

    /// Reverse the octets of an IPv4 address for DNSBL queries.
    fn reverse_ip(ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                Some(format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0]))
            }
            IpAddr::V6(_) => {
                // Most DNSBLs do not support IPv6; skip.
                None
            }
        }
    }

    async fn query_zone(&self, reversed: &str, zone: &DnsblZone) -> Option<(String, f64, bool)> {
        let query = format!("{}.{}", reversed, zone.zone);
        match self.resolver.lookup_ip(&query).await {
            Ok(response) => {
                // Any A record response means listed.
                if response.iter().next().is_some() {
                    let severity = self.weight * zone.weight_multiplier;
                    Some((zone.zone.clone(), severity, zone.reject_on_hit))
                } else {
                    None
                }
            }
            Err(_) => None, // NXDOMAIN = not listed
        }
    }
}

#[async_trait]
impl PreDataCheck for DnsblCheck {
    fn name(&self) -> &str {
        "dnsbl"
    }

    async fn check(&self, ctx: &EnvelopeContext) -> (CheckOutcome, Option<ScoreContribution>) {
        let reversed = match Self::reverse_ip(ctx.client_ip) {
            Some(r) => r,
            None => {
                return (
                    CheckOutcome::Skip {
                        reason: "IPv6 not supported for DNSBL".to_string(),
                    },
                    None,
                );
            }
        };

        // Query all zones in parallel.
        let futures: Vec<_> = self
            .zones
            .iter()
            .map(|zone| self.query_zone(&reversed, zone))
            .collect();
        let results: Vec<Option<(String, f64, bool)>> = futures::future::join_all(futures).await;

        let mut total_severity: f64 = 0.0;
        let mut listed_zones: Vec<String> = Vec::new();

        for result in results.into_iter().flatten() {
            let (zone, severity, reject) = result;
            if reject {
                return (
                    CheckOutcome::Reject {
                        reason: format!("Listed in DNSBL {}", zone),
                    },
                    Some(ScoreContribution {
                        check_name: "dnsbl".to_string(),
                        category: CheckCategory::Reputation,
                        score: severity,
                        description: format!("IP {} listed in {}", ctx.client_ip, zone),
                    }),
                );
            }
            total_severity += severity;
            listed_zones.push(zone);
        }

        if listed_zones.is_empty() {
            (CheckOutcome::Pass, None)
        } else {
            let detail = format!("Listed in: {}", listed_zones.join(", "));
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: detail.clone(),
                },
                Some(ScoreContribution {
                    check_name: "dnsbl".to_string(),
                    category: CheckCategory::Reputation,
                    score: total_severity,
                    description: detail,
                }),
            )
        }
    }
}
