use std::sync::Arc;

use async_trait::async_trait;
use mail_auth::{AuthenticatedMessage, DkimResult, Resolver};

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Validates ARC (Authenticated Received Chain) headers for forwarded messages.
pub struct ArcCheck {
    pub weight: f64,
    resolver: Arc<Resolver>,
}

impl ArcCheck {
    pub fn new(weight: f64) -> Self {
        let resolver = Arc::new(
            Resolver::new_system_conf().unwrap_or_else(|_| Resolver::new_cloudflare_tls().unwrap()),
        );
        Self { weight, resolver }
    }
}

#[async_trait]
impl PostDataCheck for ArcCheck {
    fn name(&self) -> &str {
        "arc"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let authenticated_msg = match AuthenticatedMessage::parse(&ctx.raw_message) {
            Some(msg) => msg,
            None => {
                return (
                    CheckOutcome::Skip {
                        reason: "Failed to parse message for ARC".to_string(),
                    },
                    Vec::new(),
                );
            }
        };

        let arc_result = self.resolver.verify_arc(&authenticated_msg).await;

        let mut contributions = Vec::new();

        match arc_result.result() {
            DkimResult::Pass => {
                (CheckOutcome::Pass, contributions)
            }
            DkimResult::Fail(_) => {
                let score = self.weight * 0.5;
                contributions.push(ScoreContribution {
                    check_name: "arc".to_string(),
                    category: CheckCategory::Authentication,
                    score,
                    description: "ARC chain validation failed".to_string(),
                });
                (
                    CheckOutcome::Hit {
                        severity: score,
                        detail: "ARC fail".to_string(),
                    },
                    contributions,
                )
            }
            DkimResult::None | DkimResult::Neutral(_) | DkimResult::PermError(_) | DkimResult::TempError(_) => {
                // No ARC headers or errors -- not penalised.
                (CheckOutcome::Pass, contributions)
            }
        }
    }
}
