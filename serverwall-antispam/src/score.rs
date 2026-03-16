use serde::{Deserialize, Serialize};

/// A numeric spam score (higher = more likely spam).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SpamScore(pub f64);

impl SpamScore {
    /// Create a new zero score.
    pub fn new() -> Self {
        Self(0.0)
    }

    /// Add a weighted contribution: weight * severity.
    pub fn add(&mut self, weight: f64, severity: f64) {
        self.0 += weight * severity;
    }

    /// Return the score normalised to a 0-100 percentage.
    ///
    /// The raw score is clamped to `[0, max_score]` then scaled linearly.
    /// A reasonable `max_score` is the theoretical maximum a message could
    /// accumulate; 50.0 is a sensible default.
    pub fn percentage(&self, max_score: f64) -> f64 {
        if max_score <= 0.0 {
            return 0.0;
        }
        let clamped = self.0.clamp(0.0, max_score);
        (clamped / max_score) * 100.0
    }

    /// Produce a verdict based on configurable thresholds (0-100 scale).
    ///
    /// * `suspect_threshold` -- percentage above which a message is suspect
    /// * `spam_threshold`    -- percentage above which a message is definite spam
    pub fn verdict(&self, max_score: f64, suspect_threshold: f64, spam_threshold: f64) -> SpamVerdict {
        let pct = self.percentage(max_score);
        if pct >= spam_threshold {
            SpamVerdict::Spam
        } else if pct >= suspect_threshold {
            SpamVerdict::Suspect
        } else {
            SpamVerdict::Clean
        }
    }
}

impl Default for SpamScore {
    fn default() -> Self {
        Self::new()
    }
}

/// Overall classification of a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpamVerdict {
    Clean,
    Suspect,
    Spam,
}

/// Category of a scoring check, used for reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckCategory {
    Authentication,
    Reputation,
    Content,
    Header,
    RateLimit,
    Behavioral,
}

/// A single score contribution from one check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreContribution {
    pub check_name: String,
    pub category: CheckCategory,
    pub score: f64,
    pub description: String,
}
