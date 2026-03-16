use crate::score::{ScoreContribution, SpamScore, SpamVerdict};

/// Outcome of a single check.
#[derive(Debug, Clone)]
pub enum CheckOutcome {
    /// The check passed cleanly (no penalty).
    Pass,
    /// The check hit something suspicious.
    Hit { severity: f64, detail: String },
    /// The check demands immediate rejection.
    Reject { reason: String },
    /// A temporary failure; ask the sender to retry.
    TempFail { reason: String },
    /// The check was skipped (disabled, not applicable, etc.).
    Skip { reason: String },
}

/// Result of an authentication mechanism (SPF / DKIM / DMARC / ARC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl std::fmt::Display for AuthResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuthResult::Pass => "pass",
            AuthResult::Fail => "fail",
            AuthResult::SoftFail => "softfail",
            AuthResult::Neutral => "neutral",
            AuthResult::None => "none",
            AuthResult::TempError => "temperror",
            AuthResult::PermError => "permerror",
        };
        f.write_str(s)
    }
}

/// Authentication results for SPF, DKIM, DMARC, ARC.
#[derive(Debug, Clone)]
pub struct AuthenticationResults {
    pub spf: AuthResult,
    pub dkim: AuthResult,
    pub dmarc: AuthResult,
    pub arc: AuthResult,
}

impl Default for AuthenticationResults {
    fn default() -> Self {
        Self {
            spf: AuthResult::None,
            dkim: AuthResult::None,
            dmarc: AuthResult::None,
            arc: AuthResult::None,
        }
    }
}

/// Full spam report for a processed message.
#[derive(Debug, Clone)]
pub struct SpamReport {
    pub score: SpamScore,
    pub verdict: SpamVerdict,
    pub contributions: Vec<ScoreContribution>,
    pub auth_results: AuthenticationResults,
}
