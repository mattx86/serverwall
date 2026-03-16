use async_trait::async_trait;
use regex::Regex;

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// A single content matching rule.
#[derive(Debug, Clone)]
pub struct ContentRule {
    pub name: String,
    pub pattern: Regex,
    pub severity: f64,
    pub description: String,
}

/// Analyzes message body content for spam patterns, keywords, and heuristics.
pub struct ContentCheck {
    pub weight: f64,
    pub rules: Vec<ContentRule>,
    /// Subject matches are weighted at 1.5x.
    pub subject_multiplier: f64,
}

impl ContentCheck {
    pub fn new(weight: f64) -> Self {
        Self {
            weight,
            rules: Self::default_rules(),
            subject_multiplier: 1.5,
        }
    }

    pub fn with_rules(weight: f64, rules: Vec<ContentRule>) -> Self {
        Self {
            weight,
            rules,
            subject_multiplier: 1.5,
        }
    }

    fn default_rules() -> Vec<ContentRule> {
        vec![
            ContentRule {
                name: "viagra".to_string(),
                pattern: Regex::new(r"(?i)\bviagra\b").unwrap(),
                severity: 0.8,
                description: "Pharmaceutical spam keyword".to_string(),
            },
            ContentRule {
                name: "cialis".to_string(),
                pattern: Regex::new(r"(?i)\bcialis\b").unwrap(),
                severity: 0.8,
                description: "Pharmaceutical spam keyword".to_string(),
            },
            ContentRule {
                name: "nigerian_prince".to_string(),
                pattern: Regex::new(r"(?i)nigerian?\s+(prince|minister|bank)").unwrap(),
                severity: 1.0,
                description: "419 scam pattern".to_string(),
            },
            ContentRule {
                name: "million_dollars".to_string(),
                pattern: Regex::new(r"(?i)\bmillion\s+(dollars|usd|euro)\b").unwrap(),
                severity: 0.6,
                description: "Financial scam keyword".to_string(),
            },
            ContentRule {
                name: "act_now".to_string(),
                pattern: Regex::new(r"(?i)\b(act\s+now|limited\s+time|urgent|expires?\s+today)\b").unwrap(),
                severity: 0.4,
                description: "Urgency spam pattern".to_string(),
            },
            ContentRule {
                name: "free_offer".to_string(),
                pattern: Regex::new(r"(?i)\b(free\s+offer|congratulations|you\s+(have\s+)?won)\b").unwrap(),
                severity: 0.5,
                description: "Free offer spam pattern".to_string(),
            },
            ContentRule {
                name: "click_here".to_string(),
                pattern: Regex::new(r"(?i)\bclick\s+here\b").unwrap(),
                severity: 0.3,
                description: "Click-bait pattern".to_string(),
            },
            ContentRule {
                name: "unsubscribe_missing".to_string(),
                pattern: Regex::new(r"(?i)\b(buy\s+now|order\s+today|special\s+offer)\b").unwrap(),
                severity: 0.4,
                description: "Commercial spam without opt-out".to_string(),
            },
        ]
    }
}

#[async_trait]
impl PostDataCheck for ContentCheck {
    fn name(&self) -> &str {
        "content"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let body_text = String::from_utf8_lossy(&ctx.raw_message);
        let mut contributions = Vec::new();
        let mut total_severity: f64 = 0.0;

        // Extract subject from raw message for weighted matching.
        let subject = body_text
            .lines()
            .find(|l| l.to_lowercase().starts_with("subject:"))
            .map(|l| l["subject:".len()..].trim().to_string())
            .unwrap_or_default();

        for rule in &self.rules {
            // Check subject with multiplier.
            if !subject.is_empty() && rule.pattern.is_match(&subject) {
                let score = self.weight * rule.severity * self.subject_multiplier;
                total_severity += score;
                contributions.push(ScoreContribution {
                    check_name: format!("content/{}", rule.name),
                    category: CheckCategory::Content,
                    score,
                    description: format!("{} (subject match, {:.1}x)", rule.description, self.subject_multiplier),
                });
                continue; // Don't double-count body match.
            }

            // Check body.
            if rule.pattern.is_match(&body_text) {
                let score = self.weight * rule.severity;
                total_severity += score;
                contributions.push(ScoreContribution {
                    check_name: format!("content/{}", rule.name),
                    category: CheckCategory::Content,
                    score,
                    description: rule.description.clone(),
                });
            }
        }

        if contributions.is_empty() {
            (CheckOutcome::Pass, contributions)
        } else {
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: format!("{} content rules matched", contributions.len()),
                },
                contributions,
            )
        }
    }
}
