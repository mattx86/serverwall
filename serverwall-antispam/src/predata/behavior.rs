use async_trait::async_trait;

use crate::pipeline::{EnvelopeContext, PreDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Rapid-fire command threshold: if the client has issued more than this
/// many commands in a very short time, flag it.
const RAPID_FIRE_THRESHOLD: u32 = 20;

/// Analyzes client SMTP behavior patterns (command ordering, timing,
/// pipelining abuse) to detect suspicious or bot-like activity.
pub struct BehaviorCheck {
    pub weight: f64,
}

impl BehaviorCheck {
    pub fn new(weight: f64) -> Self {
        Self { weight }
    }
}

#[async_trait]
impl PreDataCheck for BehaviorCheck {
    fn name(&self) -> &str {
        "behavior"
    }

    async fn check(&self, ctx: &EnvelopeContext) -> (CheckOutcome, Option<ScoreContribution>) {
        let mut total_severity: f64 = 0.0;
        let mut details: Vec<String> = Vec::new();

        // Check pipelining abuse -- sending multiple commands without
        // waiting for responses.
        if ctx.pipelining_detected {
            let sev = self.weight * 0.6;
            total_severity += sev;
            details.push("pipelining abuse detected".to_string());
        }

        // Check rapid-fire commands.
        let elapsed = ctx.banner_sent_time.elapsed();
        if ctx.command_count > RAPID_FIRE_THRESHOLD && elapsed.as_secs() < 5 {
            let sev = self.weight * 0.8;
            total_severity += sev;
            details.push(format!(
                "rapid-fire commands: {} in {:.1}s",
                ctx.command_count,
                elapsed.as_secs_f64(),
            ));
        }

        if details.is_empty() {
            (CheckOutcome::Pass, None)
        } else {
            let detail = details.join("; ");
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: detail.clone(),
                },
                Some(ScoreContribution {
                    check_name: "behavior".to_string(),
                    category: CheckCategory::Behavioral,
                    score: total_severity,
                    description: detail,
                }),
            )
        }
    }
}
