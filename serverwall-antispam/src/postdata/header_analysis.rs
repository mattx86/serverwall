use async_trait::async_trait;
use regex::Regex;

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Analyzes message headers for anomalies, forgery, and spam indicators.
pub struct HeaderAnalysisCheck {
    pub weight: f64,
    received_ip_re: Regex,
}

impl HeaderAnalysisCheck {
    pub fn new(weight: f64) -> Self {
        let received_ip_re = Regex::new(
            r"(?i)Received:\s+from\s+\S+\s+\(.*?\[(\d+\.\d+\.\d+\.\d+)\]"
        ).unwrap();

        Self {
            weight,
            received_ip_re,
        }
    }
}

#[async_trait]
impl PostDataCheck for HeaderAnalysisCheck {
    fn name(&self) -> &str {
        "header_analysis"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let raw = String::from_utf8_lossy(&ctx.raw_message);
        // Only look at headers (before first blank line).
        let header_section = raw.split("\r\n\r\n").next().unwrap_or(&raw);
        let header_lower = header_section.to_lowercase();

        let mut contributions = Vec::new();
        let mut total_severity: f64 = 0.0;

        // Missing Message-ID.
        if !header_lower.contains("\nmessage-id:") && !header_lower.starts_with("message-id:") {
            let score = self.weight * 0.5;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "header/missing_message_id".to_string(),
                category: CheckCategory::Header,
                score,
                description: "Missing Message-ID header".to_string(),
            });
        }

        // Missing Date.
        if !header_lower.contains("\ndate:") && !header_lower.starts_with("date:") {
            let score = self.weight * 0.6;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "header/missing_date".to_string(),
                category: CheckCategory::Header,
                score,
                description: "Missing Date header".to_string(),
            });
        }

        // Multiple From headers.
        let from_count = header_lower
            .lines()
            .filter(|l| l.starts_with("from:"))
            .count();
        if from_count > 1 {
            let score = self.weight * 1.0;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "header/multiple_from".to_string(),
                category: CheckCategory::Header,
                score,
                description: format!("Multiple From headers ({})", from_count),
            });
        }

        // Forged Received headers: private IPs in external Received lines.
        let received_ips: Vec<String> = self
            .received_ip_re
            .captures_iter(header_section)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .collect();

        if received_ips.len() > 1 {
            // Check for suspicious patterns: private IPs appearing after public.
            let mut seen_public = false;
            for ip_str in &received_ips {
                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                    let is_private = match ip {
                        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
                        std::net::IpAddr::V6(v6) => v6.is_loopback(),
                    };
                    if is_private && seen_public {
                        let score = self.weight * 0.4;
                        total_severity += score;
                        contributions.push(ScoreContribution {
                            check_name: "header/forged_received".to_string(),
                            category: CheckCategory::Header,
                            score,
                            description: format!("Suspicious Received chain: private IP {} after public", ip_str),
                        });
                        break;
                    }
                    if !is_private {
                        seen_public = true;
                    }
                }
            }
        }

        if contributions.is_empty() {
            (CheckOutcome::Pass, contributions)
        } else {
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: format!("{} header issues", contributions.len()),
                },
                contributions,
            )
        }
    }
}
