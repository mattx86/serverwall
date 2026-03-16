use std::sync::Arc;

use async_trait::async_trait;
use mail_auth::{AuthenticatedMessage, Resolver};

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Validates DMARC (Domain-based Message Authentication, Reporting, and
/// Conformance) policy.
pub struct DmarcCheck {
    pub weight: f64,
    pub honor_reject_policy: bool,
    resolver: Arc<Resolver>,
}

impl DmarcCheck {
    pub fn new(weight: f64, honor_reject_policy: bool) -> Self {
        let resolver = Arc::new(
            Resolver::new_system_conf().unwrap_or_else(|_| Resolver::new_cloudflare_tls().unwrap()),
        );
        Self {
            weight,
            honor_reject_policy,
            resolver,
        }
    }
}

#[async_trait]
impl PostDataCheck for DmarcCheck {
    fn name(&self) -> &str {
        "dmarc"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let authenticated_msg = match AuthenticatedMessage::parse(&ctx.raw_message) {
            Some(msg) => msg,
            None => {
                return (
                    CheckOutcome::Skip {
                        reason: "Failed to parse message for DMARC".to_string(),
                    },
                    Vec::new(),
                );
            }
        };

        // Extract domain from MAIL FROM.
        let domain = ctx
            .envelope
            .mail_from
            .rsplit_once('@')
            .map(|(_, d)| d.trim_end_matches('>').to_string())
            .unwrap_or_default();

        // Run DKIM first (needed for DMARC evaluation).
        let dkim_result = self.resolver.verify_dkim(&authenticated_msg).await;

        // Run SPF.
        let spf_result = self
            .resolver
            .verify_spf_sender(
                ctx.envelope.client_ip,
                &ctx.envelope.helo_domain,
                &domain,
                &ctx.envelope.mail_from,
            )
            .await;

        let dmarc_result = self
            .resolver
            .verify_dmarc(&authenticated_msg, &dkim_result, &domain, &spf_result)
            .await;

        let mut contributions = Vec::new();

        use mail_auth::DmarcResult;
        match dmarc_result.dkim_result() {
            DmarcResult::Pass => {
                (CheckOutcome::Pass, contributions)
            }
            DmarcResult::Fail(_) => {
                // Check if policy says reject and we honour it.
                let policy = dmarc_result.policy();
                let policy_is_reject = matches!(policy, mail_auth::dmarc::Policy::Reject);

                if self.honor_reject_policy && policy_is_reject {
                    contributions.push(ScoreContribution {
                        check_name: "dmarc".to_string(),
                        category: CheckCategory::Authentication,
                        score: self.weight,
                        description: format!("DMARC fail with p=reject for {}", domain),
                    });
                    return (
                        CheckOutcome::Reject {
                            reason: format!("DMARC policy reject for {}", domain),
                        },
                        contributions,
                    );
                }

                let score = self.weight * 0.8;
                contributions.push(ScoreContribution {
                    check_name: "dmarc".to_string(),
                    category: CheckCategory::Authentication,
                    score,
                    description: format!("DMARC fail for {}", domain),
                });
                (
                    CheckOutcome::Hit {
                        severity: score,
                        detail: format!("DMARC fail for {}", domain),
                    },
                    contributions,
                )
            }
            DmarcResult::TempError(_) | DmarcResult::PermError(_) | DmarcResult::None => {
                let score = self.weight * 0.1;
                contributions.push(ScoreContribution {
                    check_name: "dmarc".to_string(),
                    category: CheckCategory::Authentication,
                    score,
                    description: format!("No DMARC record for {}", domain),
                });
                (
                    CheckOutcome::Hit {
                        severity: score,
                        detail: format!("No DMARC record for {}", domain),
                    },
                    contributions,
                )
            }
        }
    }
}
