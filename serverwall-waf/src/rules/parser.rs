use super::rule_set::WafRule;

/// Parses WAF rule definitions from configuration files.
pub struct RuleParser;

impl RuleParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse rule definitions from a string (e.g., a custom rules config).
    ///
    /// Currently a stub that returns an empty set. Custom rule parsing
    /// will be implemented when the configuration format is finalized.
    pub fn parse(&self, _input: &str) -> Result<Vec<WafRule>, String> {
        // TODO: parse rule definitions from config format
        Ok(Vec::new())
    }
}
