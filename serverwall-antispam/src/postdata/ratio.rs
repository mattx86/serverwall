use async_trait::async_trait;
use regex::Regex;

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Analyzes text-to-image ratio, link-to-text ratio, and other structural
/// ratios that are indicative of spam.
pub struct RatioAnalysisCheck {
    pub weight: f64,
    link_re: Regex,
    img_tag_re: Regex,
}

impl RatioAnalysisCheck {
    pub fn new(weight: f64) -> Self {
        let link_re = Regex::new(r"(?i)<a\s").unwrap();
        let img_tag_re = Regex::new(r"(?i)<img\s").unwrap();

        Self {
            weight,
            link_re,
            img_tag_re,
        }
    }
}

#[async_trait]
impl PostDataCheck for RatioAnalysisCheck {
    fn name(&self) -> &str {
        "ratio"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let body_text = String::from_utf8_lossy(&ctx.raw_message);
        let body_section = body_text.split("\r\n\r\n").nth(1).unwrap_or("");

        let mut contributions = Vec::new();
        let mut total_severity: f64 = 0.0;

        let text_len = body_section
            .chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace())
            .count();

        // Link density: links / text_length.
        let link_count = self.link_re.find_iter(body_section).count();
        if text_len > 0 && link_count > 0 {
            let link_density = link_count as f64 / (text_len as f64 / 100.0);
            if link_density > 5.0 {
                let score = self.weight * 0.5;
                total_severity += score;
                contributions.push(ScoreContribution {
                    check_name: "ratio/link_density".to_string(),
                    category: CheckCategory::Content,
                    score,
                    description: format!("High link density: {:.1} links per 100 chars", link_density),
                });
            }
        }

        // Image-to-text ratio.
        let img_count = self.img_tag_re.find_iter(body_section).count();
        if img_count > 0 && text_len < 50 {
            let score = self.weight * 0.6;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "ratio/image_heavy".to_string(),
                category: CheckCategory::Content,
                score,
                description: format!("{} images with only {} chars of text", img_count, text_len),
            });
        }

        // HTML-to-text ratio: if body is mostly HTML tags.
        let html_tag_count = body_section.matches('<').count();
        if text_len > 0 {
            let tag_ratio = html_tag_count as f64 / text_len as f64;
            if tag_ratio > 1.0 && html_tag_count > 20 {
                let score = self.weight * 0.3;
                total_severity += score;
                contributions.push(ScoreContribution {
                    check_name: "ratio/html_heavy".to_string(),
                    category: CheckCategory::Content,
                    score,
                    description: format!("High HTML-to-text ratio: {:.1}", tag_ratio),
                });
            }
        }

        if contributions.is_empty() {
            (CheckOutcome::Pass, contributions)
        } else {
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: format!("{} ratio issues", contributions.len()),
                },
                contributions,
            )
        }
    }
}
