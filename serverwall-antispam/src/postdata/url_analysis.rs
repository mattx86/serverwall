use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use regex::Regex;

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Threshold for "excessive" URLs in a single message.
const EXCESSIVE_URL_THRESHOLD: usize = 15;

/// Extracts and analyzes URLs in the message body for phishing and malicious links.
pub struct UrlAnalysisCheck {
    pub weight: f64,
    pub surbl_zones: Vec<String>,
    url_re: Regex,
    resolver: Arc<TokioAsyncResolver>,
}

impl UrlAnalysisCheck {
    pub fn new(weight: f64, surbl_zones: Vec<String>) -> Self {
        let url_re =
            Regex::new(r"https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})(?:[/\?\#]|$)").unwrap();
        let resolver = Arc::new(
            TokioAsyncResolver::tokio_from_system_conf()
                .unwrap_or_else(|_| TokioAsyncResolver::tokio(
                    hickory_resolver::config::ResolverConfig::default(),
                    hickory_resolver::config::ResolverOpts::default(),
                )),
        );
        Self {
            weight,
            surbl_zones,
            url_re,
            resolver,
        }
    }

    /// Extract unique domains from URLs found in text.
    fn extract_domains(&self, text: &str) -> Vec<String> {
        let mut domains: Vec<String> = self
            .url_re
            .captures_iter(text)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_lowercase()))
            .collect();
        domains.sort();
        domains.dedup();
        domains
    }

    /// Query SURBL for a domain.
    async fn check_surbl(&self, domain: &str, zone: &str) -> bool {
        let query = format!("{}.{}", domain, zone);
        self.resolver.lookup_ip(&query).await.is_ok()
    }
}

#[async_trait]
impl PostDataCheck for UrlAnalysisCheck {
    fn name(&self) -> &str {
        "url_analysis"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let body_text = String::from_utf8_lossy(&ctx.raw_message);
        let domains = self.extract_domains(&body_text);
        let url_count = self.url_re.find_iter(&body_text).count();

        let mut contributions = Vec::new();
        let mut total_severity: f64 = 0.0;

        // Excessive URLs check.
        if url_count > EXCESSIVE_URL_THRESHOLD {
            let score = self.weight * 0.5;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "url_analysis/excessive".to_string(),
                category: CheckCategory::Content,
                score,
                description: format!("Excessive URLs: {} found", url_count),
            });
        }

        // SURBL checks for each unique domain.
        for domain in &domains {
            for zone in &self.surbl_zones {
                if self.check_surbl(domain, zone).await {
                    let score = self.weight * 1.0;
                    total_severity += score;
                    contributions.push(ScoreContribution {
                        check_name: "url_analysis/surbl".to_string(),
                        category: CheckCategory::Reputation,
                        score,
                        description: format!("Domain {} listed in {}", domain, zone),
                    });
                }
            }
        }

        if contributions.is_empty() {
            (CheckOutcome::Pass, contributions)
        } else {
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: format!("{} URL issues found", contributions.len()),
                },
                contributions,
            )
        }
    }
}
