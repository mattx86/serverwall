use std::path::Path;

use serverwall_core::config::schema::{WafCustomRule, WafRulesetConfig};

use super::rule_set::{RuleOperator, RuleTarget, Severity, Transformation, WafRule};

/// Parses WAF rule definitions from configuration.
pub struct RuleParser;

impl RuleParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse rule definitions from a string (legacy stub, kept for API compatibility).
    pub fn parse(&self, _input: &str) -> Result<Vec<WafRule>, String> {
        Ok(Vec::new())
    }

    /// Parse custom rules from a `WafRulesetConfig`, including inline rules and
    /// any rules loaded from `rules_dir`.
    pub fn from_ruleset_config(&self, config: &WafRulesetConfig) -> Vec<WafRule> {
        let mut rules = Vec::new();

        // Parse inline custom rules
        for custom in &config.custom_rules {
            if let Some(rule) = self.convert_custom_rule(custom) {
                rules.push(rule);
            }
        }

        // Load rules from rules_dir if configured
        if let Some(ref dir) = config.rules_dir {
            rules.extend(self.load_from_dir(dir));
        }

        rules
    }

    /// Load rules from all *.toml files in a directory.
    fn load_from_dir(&self, dir: &Path) -> Vec<WafRule> {
        let mut rules = Vec::new();

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "failed to read WAF rules directory");
                return rules;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(file = %path.display(), error = %e, "failed to read WAF rules file");
                    continue;
                }
            };

            let custom_rules: Vec<WafCustomRule> = match toml::from_str(&content) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(file = %path.display(), error = %e, "failed to parse WAF rules TOML");
                    continue;
                }
            };

            for custom in &custom_rules {
                if let Some(rule) = self.convert_custom_rule(custom) {
                    rules.push(rule);
                }
            }
        }

        rules
    }

    /// Convert a `WafCustomRule` config entry to a `WafRule` engine type.
    fn convert_custom_rule(&self, custom: &WafCustomRule) -> Option<WafRule> {
        let target = match self.parse_target(&custom.match_field) {
            Some(t) => t,
            None => {
                tracing::warn!(
                    rule_id = custom.id,
                    match_field = %custom.match_field,
                    "unknown WAF rule match_field, skipping rule",
                );
                return None;
            }
        };

        let pattern = self.operator_to_pattern(&custom.operator, &custom.pattern);

        Some(WafRule {
            id: custom.id as u32,
            description: custom.description.clone(),
            targets: vec![target],
            operator: RuleOperator::Regex,
            pattern,
            transformations: vec![Transformation::Lowercase],
            severity: Severity::Error as u8,
            score: 5,
            paranoia_level: 1,
        })
    }

    fn parse_target(&self, match_field: &str) -> Option<RuleTarget> {
        match match_field.to_lowercase().as_str() {
            "uri" | "request_uri" => Some(RuleTarget::RequestUri),
            "path" => Some(RuleTarget::Path),
            "query" | "query_string" | "args" => Some(RuleTarget::QueryString),
            "body" | "request_body" => Some(RuleTarget::RequestBody),
            "headers" | "request_headers" => Some(RuleTarget::RequestHeaders),
            "user_agent" | "ua" => Some(RuleTarget::UserAgent),
            "cookie" | "cookies" => Some(RuleTarget::Cookies),
            "remote_addr" | "ip" => Some(RuleTarget::RemoteAddr),
            _ => None,
        }
    }

    /// Convert an operator + raw pattern to a final regex pattern string.
    fn operator_to_pattern(&self, operator: &str, pattern: &str) -> String {
        match operator.to_lowercase().as_str() {
            "regex" | "rx" => pattern.to_string(),
            "contains" | "contains_word" => regex::escape(pattern),
            "equals" | "eq" | "streq" => format!("^{}$", regex::escape(pattern)),
            "starts_with" | "beginswith" => format!("^{}", regex::escape(pattern)),
            "ends_with" | "endswith" => format!("{}$", regex::escape(pattern)),
            // Special detection operators: use pattern as-is (caller provides regex)
            "detect_sqli" | "detect_xss" => pattern.to_string(),
            _ => {
                tracing::warn!(
                    operator = %operator,
                    "unknown WAF rule operator, treating as regex",
                );
                pattern.to_string()
            }
        }
    }
}
