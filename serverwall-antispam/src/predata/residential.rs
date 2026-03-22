use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use mail_auth::Resolver;
use regex::Regex;

use crate::pipeline::{EnvelopeContext, PreDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Matches residential/consumer ISP keywords anywhere in a PTR hostname.
/// Broader than rdns.rs (which only checks prefixes) because we need to catch
/// patterns like "pool-12-34-56-78.dynamic.isp.com" or "12.34.56.78.dsl.provider.net".
const RESIDENTIAL_PATTERN: &str =
    r"(?i)(^|[.\-])(dynamic|dyn|dhcp|dsl|cable|adsl|broadband|ppp|pppoe|dial|mob|mobile|gprs|lte|residential|home|fiber|fibre)[.\-]";

/// Detects residential/consumer-ISP senders and enforces SPF.
///
/// A sender is classified as residential if any of the following are true:
/// - No PTR (reverse DNS) record for the connecting IP
/// - PTR hostname contains a residential ISP keyword (dynamic, dsl, cable, etc.)
/// - The IP appears in the Spamhaus PBL or a configured equivalent zone (IPv4 only)
///
/// Once classified as residential, SPF is verified:
/// - SPF Pass        → allowed (legitimate sender who has set up SPF)
/// - SPF None/Fail/SoftFail → rejected (550)
/// - SPF Neutral     → rejected if `neutral_triggers` is true
/// - SPF TempError   → deferred (451)
/// - SPF PermError   → allowed (broken SPF record; don't punish on uncertainty)
///
/// Null MAIL FROM (`<>`) is skipped entirely (bounce messages are not spam).
pub struct ResidentialSenderCheck {
    pub weight: f64,
    pub reject: bool,
    pub check_pbl: bool,
    pub pbl_zone: String,
    pub softfail_triggers: bool,
    pub neutral_triggers: bool,
    resolver: Arc<TokioAsyncResolver>,
    mail_resolver: Arc<Resolver>,
    residential_re: Regex,
}

impl ResidentialSenderCheck {
    pub fn new(
        weight: f64,
        reject: bool,
        check_pbl: bool,
        pbl_zone: String,
        softfail_triggers: bool,
        neutral_triggers: bool,
    ) -> Self {
        let resolver = Arc::new(
            TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
                TokioAsyncResolver::tokio(
                    hickory_resolver::config::ResolverConfig::default(),
                    hickory_resolver::config::ResolverOpts::default(),
                )
            }),
        );
        let mail_resolver = Arc::new(
            Resolver::new_system_conf()
                .unwrap_or_else(|_| Resolver::new_cloudflare_tls().unwrap()),
        );
        let residential_re = Regex::new(RESIDENTIAL_PATTERN).unwrap();
        Self {
            weight,
            reject,
            check_pbl,
            pbl_zone,
            softfail_triggers,
            neutral_triggers,
            resolver,
            mail_resolver,
            residential_re,
        }
    }

    /// Queries a DNSBL zone for the given IPv4 address.
    /// Returns true if the IP is listed.
    async fn query_dnsbl(&self, ip: std::net::Ipv4Addr, zone: &str) -> bool {
        let octets = ip.octets();
        let query = format!(
            "{}.{}.{}.{}.{}",
            octets[3], octets[2], octets[1], octets[0], zone
        );
        self.resolver.lookup_ip(query.as_str()).await.is_ok()
    }

    fn reject_outcome(
        &self,
        ip: IpAddr,
        domain: &str,
        residential_reason: &str,
        spf_detail: &str,
    ) -> (CheckOutcome, Option<ScoreContribution>) {
        let reason = format!(
            "Residential sender ({}) with {} for {} from {}",
            residential_reason, spf_detail, domain, ip
        );
        if self.reject {
            (
                CheckOutcome::Reject {
                    reason: reason.clone(),
                },
                Some(ScoreContribution {
                    check_name: "residential_spf".to_string(),
                    category: CheckCategory::Reputation,
                    score: self.weight,
                    description: reason,
                }),
            )
        } else {
            (
                CheckOutcome::Hit {
                    severity: self.weight,
                    detail: reason.clone(),
                },
                Some(ScoreContribution {
                    check_name: "residential_spf".to_string(),
                    category: CheckCategory::Reputation,
                    score: self.weight,
                    description: reason,
                }),
            )
        }
    }
}

#[async_trait]
impl PreDataCheck for ResidentialSenderCheck {
    fn name(&self) -> &str {
        "residential_spf"
    }

    async fn check(&self, ctx: &EnvelopeContext) -> (CheckOutcome, Option<ScoreContribution>) {
        // Skip bounce messages (null MAIL FROM).
        let mail_from = ctx.mail_from.trim();
        if mail_from.is_empty() || mail_from == "<>" {
            return (
                CheckOutcome::Skip {
                    reason: "null MAIL FROM (bounce)".to_string(),
                },
                None,
            );
        }

        // Extract sender domain for SPF and error messages.
        let domain = match mail_from.rsplit_once('@') {
            Some((_, d)) => d.trim_end_matches('>').to_string(),
            None => {
                return (
                    CheckOutcome::Skip {
                        reason: "no domain in MAIL FROM".to_string(),
                    },
                    None,
                );
            }
        };

        let ip = ctx.client_ip;

        // ── Stage 1: Residential Detection ──────────────────────────────────

        let mut is_residential = false;
        let mut residential_reason = String::new();

        // PTR lookup.
        match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                let ptr_names: Vec<String> = lookup
                    .iter()
                    .map(|n| n.to_string().trim_end_matches('.').to_string())
                    .collect();

                if ptr_names.is_empty() {
                    is_residential = true;
                    residential_reason = "no PTR record".to_string();
                } else {
                    // Check each PTR name; use the first match.
                    for name in &ptr_names {
                        if self.residential_re.is_match(name) {
                            is_residential = true;
                            residential_reason = format!("residential PTR: {}", name);
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                is_residential = true;
                residential_reason = "no PTR record".to_string();
            }
        }

        // PBL lookup (IPv4 only, if enabled and not already classified).
        if !is_residential && self.check_pbl {
            if let IpAddr::V4(ipv4) = ip {
                if self.query_dnsbl(ipv4, &self.pbl_zone).await {
                    is_residential = true;
                    residential_reason = format!("listed in {}", self.pbl_zone);
                }
            }
        }

        if !is_residential {
            return (CheckOutcome::Skip { reason: "non-residential IP".to_string() }, None);
        }

        // ── Stage 2: SPF Verification ────────────────────────────────────────

        let spf = self
            .mail_resolver
            .verify_spf_sender(ip, &ctx.helo_domain, &domain, mail_from)
            .await;

        use mail_auth::SpfResult;
        match spf.result() {
            SpfResult::Pass => (
                CheckOutcome::Skip {
                    reason: format!(
                        "residential IP {} has valid SPF for {} — allowed",
                        ip, domain
                    ),
                },
                None,
            ),

            SpfResult::Fail => self.reject_outcome(
                ip,
                &domain,
                &residential_reason,
                "SPF fail",
            ),

            SpfResult::SoftFail => {
                if self.softfail_triggers {
                    self.reject_outcome(ip, &domain, &residential_reason, "SPF softfail")
                } else {
                    let score = self.weight * 0.5;
                    (
                        CheckOutcome::Hit {
                            severity: score,
                            detail: format!(
                                "Residential sender ({}) with SPF softfail for {}",
                                residential_reason, domain
                            ),
                        },
                        Some(ScoreContribution {
                            check_name: "residential_spf".to_string(),
                            category: CheckCategory::Reputation,
                            score,
                            description: format!(
                                "Residential IP {} SPF softfail for {}",
                                ip, domain
                            ),
                        }),
                    )
                }
            }

            SpfResult::Neutral => {
                if self.neutral_triggers {
                    self.reject_outcome(ip, &domain, &residential_reason, "SPF neutral")
                } else {
                    let score = self.weight * 0.3;
                    (
                        CheckOutcome::Hit {
                            severity: score,
                            detail: format!(
                                "Residential sender ({}) with SPF neutral for {}",
                                residential_reason, domain
                            ),
                        },
                        Some(ScoreContribution {
                            check_name: "residential_spf".to_string(),
                            category: CheckCategory::Reputation,
                            score,
                            description: format!(
                                "Residential IP {} SPF neutral for {}",
                                ip, domain
                            ),
                        }),
                    )
                }
            }

            SpfResult::None => self.reject_outcome(
                ip,
                &domain,
                &residential_reason,
                "no SPF record",
            ),

            SpfResult::TempError => (
                CheckOutcome::TempFail {
                    reason: format!(
                        "Residential IP {} but SPF lookup failed for {} — deferring",
                        ip, domain
                    ),
                },
                None,
            ),

            SpfResult::PermError => (
                // Broken SPF record — don't punish on uncertainty.
                CheckOutcome::Skip {
                    reason: format!("SPF PermError for {} — skipping residential enforcement", domain),
                },
                None,
            ),
        }
    }
}
