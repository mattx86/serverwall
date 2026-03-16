/// Accumulates anomaly scores from multiple rule matches and determines
/// whether the total score exceeds a threshold.
#[derive(Debug, Clone)]
pub struct AnomalyScorer {
    pub threshold: u32,
    pub current_score: u32,
    pub matched_rule_ids: Vec<String>,
}

impl AnomalyScorer {
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            current_score: 0,
            matched_rule_ids: Vec::new(),
        }
    }

    /// Add score from a matched rule, recording its identifier.
    pub fn add_match(&mut self, rule_id: &str, score: u32) {
        self.current_score = self.current_score.saturating_add(score);
        self.matched_rule_ids.push(rule_id.to_string());
    }

    /// Add a raw score without recording a rule id.
    pub fn add_score(&mut self, score: u32) {
        self.current_score = self.current_score.saturating_add(score);
    }

    /// Check if the accumulated score meets or exceeds the threshold.
    pub fn is_anomalous(&self) -> bool {
        self.current_score >= self.threshold
    }

    /// Reset the scorer for reuse.
    pub fn reset(&mut self) {
        self.current_score = 0;
        self.matched_rule_ids.clear();
    }
}
