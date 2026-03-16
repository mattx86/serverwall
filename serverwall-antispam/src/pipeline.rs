use std::net::IpAddr;
use std::time::Instant;

use async_trait::async_trait;
use serverwall_core::config::schema::AntispamConfig;

use crate::result::{AuthenticationResults, CheckOutcome, SpamReport};
use crate::score::{ScoreContribution, SpamScore};

/// Envelope-level context available before message DATA.
pub struct EnvelopeContext {
    pub client_ip: IpAddr,
    pub helo_domain: String,
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    /// Whether the client sent data before the banner (early talker).
    pub early_talker: bool,
    /// Time the connection was accepted.
    pub connect_time: Instant,
    /// Time the banner was sent.
    pub banner_sent_time: Instant,
    /// Number of commands issued so far.
    pub command_count: u32,
    /// Whether pipelining abuse was detected.
    pub pipelining_detected: bool,
}

impl EnvelopeContext {
    /// Convenience constructor for contexts where timing is not relevant.
    pub fn new(client_ip: IpAddr, helo_domain: String, mail_from: String, rcpt_to: Vec<String>) -> Self {
        let now = Instant::now();
        Self {
            client_ip,
            helo_domain,
            mail_from,
            rcpt_to,
            early_talker: false,
            connect_time: now,
            banner_sent_time: now,
            command_count: 0,
            pipelining_detected: false,
        }
    }
}

/// Full message context available after DATA.
pub struct MessageContext {
    pub envelope: EnvelopeContext,
    pub raw_message: Vec<u8>,
}

/// The decision produced by a single pipeline check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineDecision {
    /// Continue to the next check.
    Continue,
    /// Accept the message immediately (whitelist hit).
    Accept,
    /// Reject the message with an SMTP reply code.
    Reject(u16, String),
    /// Temporary failure; ask the sender to retry.
    TempFail(String),
}

/// A check that runs before the message DATA phase (envelope-only).
#[async_trait]
pub trait PreDataCheck: Send + Sync {
    fn name(&self) -> &str;
    async fn check(&self, ctx: &EnvelopeContext) -> (CheckOutcome, Option<ScoreContribution>);
}

/// A check that runs after the full message has been received.
#[async_trait]
pub trait PostDataCheck: Send + Sync {
    fn name(&self) -> &str;
    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>);
}

// ---- Default max-score for normalisation ----
const DEFAULT_MAX_SCORE: f64 = 50.0;

/// Orchestrates pre-data and post-data checks in order.
pub struct AntispamPipeline {
    config: AntispamConfig,
    pre_data_checks: Vec<Box<dyn PreDataCheck>>,
    post_data_checks: Vec<Box<dyn PostDataCheck>>,
}

impl AntispamPipeline {
    pub fn new(
        config: AntispamConfig,
        pre_data_checks: Vec<Box<dyn PreDataCheck>>,
        post_data_checks: Vec<Box<dyn PostDataCheck>>,
    ) -> Self {
        Self {
            config,
            pre_data_checks,
            post_data_checks,
        }
    }

    /// Create an empty pipeline (no checks loaded).
    pub fn empty() -> Self {
        Self {
            config: AntispamConfig::default(),
            pre_data_checks: Vec::new(),
            post_data_checks: Vec::new(),
        }
    }

    /// Run all pre-DATA checks sequentially, short-circuiting on Reject.
    pub async fn run_pre_data(&self, ctx: &EnvelopeContext) -> (PipelineDecision, SpamScore, Vec<ScoreContribution>) {
        let mut score = SpamScore::new();
        let mut contributions = Vec::new();

        for check in &self.pre_data_checks {
            let (outcome, contribution) = check.check(ctx).await;

            match outcome {
                CheckOutcome::Reject { reason } => {
                    tracing::info!(check = check.name(), reason = %reason, "pre-data check rejected");
                    return (PipelineDecision::Reject(550, reason), score, contributions);
                }
                CheckOutcome::TempFail { reason } => {
                    tracing::info!(check = check.name(), reason = %reason, "pre-data check tempfail");
                    return (PipelineDecision::TempFail(reason), score, contributions);
                }
                CheckOutcome::Hit { severity, detail } => {
                    tracing::debug!(check = check.name(), severity, detail = %detail, "pre-data hit");
                }
                CheckOutcome::Pass | CheckOutcome::Skip { .. } => {}
            }

            if let Some(c) = contribution {
                score.add(1.0, c.score);
                contributions.push(c);
            }
        }

        (PipelineDecision::Continue, score, contributions)
    }

    /// Run all post-DATA checks concurrently, then aggregate scores.
    ///
    /// Returns a `SpamReport` or a `PipelineDecision` if a check demands
    /// rejection.
    pub async fn run_post_data(
        &self,
        ctx: &MessageContext,
        pre_score: SpamScore,
        pre_contributions: Vec<ScoreContribution>,
        auth_results: AuthenticationResults,
    ) -> Result<SpamReport, PipelineDecision> {
        let mut score = pre_score;
        let mut contributions = pre_contributions;

        // Run all post-data checks concurrently.
        let futures: Vec<_> = self
            .post_data_checks
            .iter()
            .map(|check| check.check(ctx))
            .collect();

        let results = futures::future::join_all(futures).await;

        for (i, (outcome, contribs)) in results.into_iter().enumerate() {
            let check_name = self.post_data_checks[i].name();

            match outcome {
                CheckOutcome::Reject { reason } => {
                    tracing::info!(check = check_name, reason = %reason, "post-data check rejected");
                    return Err(PipelineDecision::Reject(550, reason));
                }
                CheckOutcome::TempFail { reason } => {
                    tracing::info!(check = check_name, reason = %reason, "post-data check tempfail");
                    return Err(PipelineDecision::TempFail(reason));
                }
                CheckOutcome::Hit { severity, detail } => {
                    tracing::debug!(check = check_name, severity, detail = %detail, "post-data hit");
                }
                CheckOutcome::Pass | CheckOutcome::Skip { .. } => {}
            }

            for c in contribs {
                score.add(1.0, c.score);
                contributions.push(c);
            }
        }

        let suspect_threshold = self.config.possible_spam_threshold as f64;
        let spam_threshold = self.config.definite_spam_threshold as f64;
        let verdict = score.verdict(DEFAULT_MAX_SCORE, suspect_threshold, spam_threshold);

        Ok(SpamReport {
            score,
            verdict,
            contributions,
            auth_results,
        })
    }
}
