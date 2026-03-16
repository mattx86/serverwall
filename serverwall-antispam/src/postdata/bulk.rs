use async_trait::async_trait;

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Detects bulk/mass mailing patterns using header analysis.
pub struct BulkDetectionCheck {
    pub weight: f64,
}

impl BulkDetectionCheck {
    pub fn new(weight: f64) -> Self {
        Self { weight }
    }
}

#[async_trait]
impl PostDataCheck for BulkDetectionCheck {
    fn name(&self) -> &str {
        "bulk"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let raw = String::from_utf8_lossy(&ctx.raw_message);
        let header_section = raw.split("\r\n\r\n").next().unwrap_or(&raw);
        let header_lower = header_section.to_lowercase();

        let mut contributions = Vec::new();
        let mut total_severity: f64 = 0.0;

        // Check Precedence header: bulk / junk / list.
        let is_bulk_precedence = header_lower
            .lines()
            .any(|l| {
                l.starts_with("precedence:")
                    && (l.contains("bulk") || l.contains("junk") || l.contains("list"))
            });

        // Check for List-Unsubscribe header (RFC 2369).
        let has_list_unsub = header_lower.contains("list-unsubscribe:");
        let has_list_id = header_lower.contains("list-id:");

        if is_bulk_precedence && !has_list_unsub {
            // Bulk mail without proper List-Unsubscribe -- suspicious.
            let score = self.weight * 0.6;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "bulk/no_unsubscribe".to_string(),
                category: CheckCategory::Content,
                score,
                description: "Bulk Precedence header without List-Unsubscribe".to_string(),
            });
        } else if is_bulk_precedence {
            // Bulk mail with proper unsubscribe -- mild flag.
            let score = self.weight * 0.1;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "bulk/precedence".to_string(),
                category: CheckCategory::Content,
                score,
                description: "Bulk Precedence header present".to_string(),
            });
        }

        // Mailing list without List-ID.
        if has_list_unsub && !has_list_id {
            let score = self.weight * 0.2;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "bulk/no_list_id".to_string(),
                category: CheckCategory::Content,
                score,
                description: "List-Unsubscribe without List-ID".to_string(),
            });
        }

        if contributions.is_empty() {
            (CheckOutcome::Pass, contributions)
        } else {
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: format!("{} bulk indicators", contributions.len()),
                },
                contributions,
            )
        }
    }
}
