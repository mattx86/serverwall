use std::sync::Arc;

use async_trait::async_trait;
use mail_auth::{AuthenticatedMessage, Resolver};

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Validates DKIM (DomainKeys Identified Mail) signatures on the message.
pub struct DkimCheck {
    pub weight: f64,
    resolver: Arc<Resolver>,
}

impl DkimCheck {
    pub fn new(weight: f64) -> Self {
        let resolver = Arc::new(
            Resolver::new_system_conf().unwrap_or_else(|_| Resolver::new_cloudflare_tls().unwrap()),
        );
        Self { weight, resolver }
    }
}

#[async_trait]
impl PostDataCheck for DkimCheck {
    fn name(&self) -> &str {
        "dkim"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let authenticated_msg = match AuthenticatedMessage::parse(&ctx.raw_message) {
            Some(msg) => msg,
            None => {
                return (
                    CheckOutcome::Skip {
                        reason: "Failed to parse message for DKIM".to_string(),
                    },
                    Vec::new(),
                );
            }
        };

        let result = self.resolver.verify_dkim(&authenticated_msg).await;

        let mut contributions = Vec::new();
        let mut any_pass = false;
        let mut any_fail = false;

        for output in result.iter() {
            use mail_auth::DkimResult;
            match output.result() {
                DkimResult::Pass => {
                    any_pass = true;
                }
                DkimResult::Fail(_) => {
                    any_fail = true;
                }
                DkimResult::Neutral(_)
                | DkimResult::None
                | DkimResult::PermError(_)
                | DkimResult::TempError(_) => {}
            }
        }

        if any_fail && !any_pass {
            let score = self.weight * 1.0;
            contributions.push(ScoreContribution {
                check_name: "dkim".to_string(),
                category: CheckCategory::Authentication,
                score,
                description: "DKIM signature verification failed".to_string(),
            });
            (
                CheckOutcome::Hit {
                    severity: score,
                    detail: "DKIM fail".to_string(),
                },
                contributions,
            )
        } else if !any_pass && !any_fail {
            let score = self.weight * 0.2;
            contributions.push(ScoreContribution {
                check_name: "dkim".to_string(),
                category: CheckCategory::Authentication,
                score,
                description: "No DKIM signature present".to_string(),
            });
            (
                CheckOutcome::Hit {
                    severity: score,
                    detail: "No DKIM signature".to_string(),
                },
                contributions,
            )
        } else {
            (CheckOutcome::Pass, contributions)
        }
    }
}
