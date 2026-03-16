use async_trait::async_trait;

use crate::pipeline::{EnvelopeContext, PreDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Detects clients that sent data before the server banner was sent
/// (early talkers), which is a common spambot behavior.
pub struct EarlyTalkerCheck {
    pub weight: f64,
}

impl EarlyTalkerCheck {
    pub fn new(weight: f64) -> Self {
        Self { weight }
    }
}

#[async_trait]
impl PreDataCheck for EarlyTalkerCheck {
    fn name(&self) -> &str {
        "early_talker"
    }

    async fn check(&self, ctx: &EnvelopeContext) -> (CheckOutcome, Option<ScoreContribution>) {
        if ctx.early_talker {
            let score = self.weight * 1.0;
            (
                CheckOutcome::Hit {
                    severity: score,
                    detail: format!("Client {} sent data before banner", ctx.client_ip),
                },
                Some(ScoreContribution {
                    check_name: "early_talker".to_string(),
                    category: CheckCategory::Behavioral,
                    score,
                    description: "Client sent data before banner".to_string(),
                }),
            )
        } else {
            (CheckOutcome::Pass, None)
        }
    }
}
