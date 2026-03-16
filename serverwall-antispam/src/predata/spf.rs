use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use mail_auth::Resolver;

use crate::pipeline::{EnvelopeContext, PreDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// SPF severity configuration (mirrors config schema).
#[derive(Debug, Clone)]
pub struct SpfSeverity {
    pub fail: f64,
    pub softfail: f64,
    pub neutral: f64,
    pub none: f64,
}

impl Default for SpfSeverity {
    fn default() -> Self {
        Self {
            fail: 1.0,
            softfail: 0.5,
            neutral: 0.1,
            none: 0.3,
        }
    }
}

/// Validates SPF (Sender Policy Framework) records for the envelope sender.
pub struct SpfCheck {
    pub weight: f64,
    pub severity: SpfSeverity,
    resolver: Arc<Resolver>,
}

impl SpfCheck {
    pub fn new(weight: f64, severity: SpfSeverity) -> Self {
        let resolver = Arc::new(
            Resolver::new_system_conf().unwrap_or_else(|_| Resolver::new_cloudflare_tls().unwrap()),
        );
        Self {
            weight,
            severity,
            resolver,
        }
    }
}

#[async_trait]
impl PreDataCheck for SpfCheck {
    fn name(&self) -> &str {
        "spf"
    }

    async fn check(&self, ctx: &EnvelopeContext) -> (CheckOutcome, Option<ScoreContribution>) {
        // Extract domain from MAIL FROM address.
        let domain = match ctx.mail_from.rsplit_once('@') {
            Some((_, d)) => d.trim_end_matches('>').to_string(),
            None => {
                return (
                    CheckOutcome::Skip {
                        reason: "no domain in MAIL FROM".to_string(),
                    },
                    None,
                );
            }
        };

        let helo = &ctx.helo_domain;
        let ip = ctx.client_ip;

        let result = self
            .resolver
            .verify_spf_sender(ip, helo, &domain, &ctx.mail_from)
            .await;

        use mail_auth::SpfResult;
        match result.result() {
            SpfResult::Pass => (CheckOutcome::Pass, None),
            SpfResult::Fail => {
                let score = self.weight * self.severity.fail;
                (
                    CheckOutcome::Hit {
                        severity: score,
                        detail: format!("SPF fail for {} from {}", domain, ip),
                    },
                    Some(ScoreContribution {
                        check_name: "spf".to_string(),
                        category: CheckCategory::Authentication,
                        score,
                        description: format!("SPF fail for {}", domain),
                    }),
                )
            }
            SpfResult::SoftFail => {
                let score = self.weight * self.severity.softfail;
                (
                    CheckOutcome::Hit {
                        severity: score,
                        detail: format!("SPF softfail for {}", domain),
                    },
                    Some(ScoreContribution {
                        check_name: "spf".to_string(),
                        category: CheckCategory::Authentication,
                        score,
                        description: format!("SPF softfail for {}", domain),
                    }),
                )
            }
            SpfResult::Neutral => {
                let score = self.weight * self.severity.neutral;
                (
                    CheckOutcome::Hit {
                        severity: score,
                        detail: format!("SPF neutral for {}", domain),
                    },
                    Some(ScoreContribution {
                        check_name: "spf".to_string(),
                        category: CheckCategory::Authentication,
                        score,
                        description: format!("SPF neutral for {}", domain),
                    }),
                )
            }
            SpfResult::None => {
                let score = self.weight * self.severity.none;
                (
                    CheckOutcome::Hit {
                        severity: score,
                        detail: format!("No SPF record for {}", domain),
                    },
                    Some(ScoreContribution {
                        check_name: "spf".to_string(),
                        category: CheckCategory::Authentication,
                        score,
                        description: format!("No SPF record for {}", domain),
                    }),
                )
            }
            SpfResult::TempError | SpfResult::PermError => (
                CheckOutcome::Skip {
                    reason: format!("SPF lookup error for {}", domain),
                },
                None,
            ),
        }
    }
}
