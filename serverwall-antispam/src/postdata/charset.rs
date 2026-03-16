use async_trait::async_trait;
use regex::Regex;

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Checks for suspicious character set usage and encoding anomalies.
pub struct CharsetCheck {
    pub weight: f64,
    zero_width_re: Regex,
}

impl CharsetCheck {
    pub fn new(weight: f64) -> Self {
        // Zero-width characters: ZWJ, ZWNJ, ZWSP, zero-width no-break space.
        let zero_width_re = Regex::new(r"[\x{200B}\x{200C}\x{200D}\x{FEFF}]").unwrap();

        Self {
            weight,
            zero_width_re,
        }
    }
}

#[async_trait]
impl PostDataCheck for CharsetCheck {
    fn name(&self) -> &str {
        "charset"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let raw = String::from_utf8_lossy(&ctx.raw_message);
        let header_section = raw.split("\r\n\r\n").next().unwrap_or(&raw);
        let header_lower = header_section.to_lowercase();

        let mut contributions = Vec::new();
        let mut total_severity: f64 = 0.0;

        // Mixed encodings: multiple charset declarations in headers.
        let charsets: Vec<&str> = header_lower
            .lines()
            .filter_map(|l| {
                if l.contains("charset=") {
                    l.split("charset=")
                        .nth(1)
                        .map(|s| s.split(|c: char| c == ';' || c == '"' || c.is_whitespace()).next().unwrap_or(""))
                } else {
                    None
                }
            })
            .filter(|s| !s.is_empty())
            .collect();

        let unique_charsets: std::collections::HashSet<_> = charsets.iter().collect();
        if unique_charsets.len() > 1 {
            let score = self.weight * 0.5;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "charset/mixed".to_string(),
                category: CheckCategory::Content,
                score,
                description: format!("Mixed charsets: {:?}", unique_charsets),
            });
        }

        // Zero-width characters in body (obfuscation technique).
        let body_section = raw.split("\r\n\r\n").nth(1).unwrap_or("");
        let zw_count = self.zero_width_re.find_iter(body_section).count();
        if zw_count > 3 {
            let score = self.weight * 0.7;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "charset/zero_width".to_string(),
                category: CheckCategory::Content,
                score,
                description: format!("{} zero-width characters found", zw_count),
            });
        }

        // Unnecessary Base64 encoding of plain ASCII text.
        if header_lower.contains("content-transfer-encoding: base64") {
            // Check if the body is actually plain ASCII.
            let body_bytes = body_section.as_bytes();
            if body_bytes.iter().all(|b| b.is_ascii()) && body_bytes.len() > 100 {
                let score = self.weight * 0.3;
                total_severity += score;
                contributions.push(ScoreContribution {
                    check_name: "charset/unnecessary_b64".to_string(),
                    category: CheckCategory::Content,
                    score,
                    description: "Unnecessary Base64 encoding of ASCII text".to_string(),
                });
            }
        }

        if contributions.is_empty() {
            (CheckOutcome::Pass, contributions)
        } else {
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: format!("{} charset issues", contributions.len()),
                },
                contributions,
            )
        }
    }
}
