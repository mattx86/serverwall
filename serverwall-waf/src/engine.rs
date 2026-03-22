use crate::anomaly::AnomalyScorer;
use crate::inspection;
use crate::request::HttpRequestContext;
use crate::response::WafDecision;
use crate::rules::matcher::RuleMatcher;
use crate::rules::parser::RuleParser;
use crate::rules::rule_set::{CompiledRuleGroup, WafRule};

/// Controls how the WAF engine behaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafMode {
    /// Actively block malicious requests.
    Blocking,
    /// Log detections but allow all traffic through.
    DetectionOnly,
    /// WAF processing is completely disabled.
    Disabled,
}

/// Request size and count limits enforced before rule inspection.
#[derive(Debug, Clone)]
pub struct RequestLimits {
    /// Maximum request body size in bytes (0 = unlimited).
    pub max_body_size: usize,
    /// Maximum number of headers allowed.
    pub max_header_count: usize,
    /// Maximum length of a single header value.
    pub max_header_value_len: usize,
    /// Maximum URI length.
    pub max_uri_length: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_body_size: 10 * 1024 * 1024, // 10 MB
            max_header_count: 100,
            max_header_value_len: 8192,
            max_uri_length: 8192,
        }
    }
}

/// The outcome of WAF inspection on a single request.
#[derive(Debug, Clone)]
pub struct WafVerdict {
    pub decision: WafDecision,
    pub matched_rules: Vec<String>,
    pub anomaly_score: u32,
}

/// Core WAF engine that evaluates requests against loaded rule sets.
pub struct WafEngine {
    pub mode: WafMode,
    anomaly_threshold: u32,
    paranoia_level: u8,
    rule_groups: Vec<CompiledRuleGroup>,
    limits: RequestLimits,
    /// URL path prefixes that bypass WAF inspection entirely.
    excluded_paths: Vec<String>,
    /// Client IPs that bypass WAF inspection entirely.
    excluded_ips: Vec<String>,
}

impl WafEngine {
    /// Create a new WAF engine with default built-in rules.
    pub fn new(mode: WafMode) -> Self {
        Self::with_config(mode, 5, 1, RequestLimits::default())
    }

    /// Create a WAF engine with specific configuration.
    pub fn with_config(
        mode: WafMode,
        anomaly_threshold: u32,
        paranoia_level: u8,
        limits: RequestLimits,
    ) -> Self {
        let all_rules = inspection::all_builtin_rules();

        // Filter rules by paranoia level
        let active_rules: Vec<_> = all_rules
            .into_iter()
            .filter(|r| r.paranoia_level <= paranoia_level)
            .collect();

        // Compile into a single rule group
        let rule_groups = CompiledRuleGroup::compile(active_rules)
            .into_iter()
            .collect();

        Self {
            mode,
            anomaly_threshold,
            paranoia_level,
            rule_groups,
            limits,
            excluded_paths: Vec::new(),
            excluded_ips: Vec::new(),
        }
    }

    /// Create a WAF engine from a full ruleset config, including custom rules.
    pub fn from_ruleset_config(config: &serverwall_core::config::schema::WafRulesetConfig) -> Self {
        use serverwall_core::config::schema::WafMode as CfgWafMode;
        let mode = match config.mode {
            CfgWafMode::Blocking => WafMode::Blocking,
            CfgWafMode::DetectionOnly => WafMode::DetectionOnly,
            CfgWafMode::Disabled => WafMode::Disabled,
        };

        let mut engine = Self::with_config(
            mode,
            config.anomaly_threshold,
            config.paranoia_level,
            RequestLimits::default(),
        );

        let custom_rules = RuleParser::new().from_ruleset_config(config);
        if !custom_rules.is_empty() {
            engine.add_custom_rules(custom_rules);
        }

        engine.excluded_paths = config.exclusions.paths.clone();
        engine.excluded_ips = config.exclusions.ip_addresses.clone();

        engine
    }

    /// Add custom rules to this engine, grouping them into `CompiledRuleGroup`s by target.
    fn add_custom_rules(&mut self, rules: Vec<WafRule>) {
        // Group by the string representation of the first target (custom rules have one target).
        let mut by_target: std::collections::HashMap<String, Vec<WafRule>> =
            std::collections::HashMap::new();
        for rule in rules {
            let key = format!("{:?}", rule.targets.first());
            by_target.entry(key).or_default().push(rule);
        }

        for (_, group_rules) in by_target {
            if let Some(compiled) = CompiledRuleGroup::compile(group_rules) {
                self.rule_groups.push(compiled);
            }
        }
    }

    /// Get the paranoia level.
    pub fn paranoia_level(&self) -> u8 {
        self.paranoia_level
    }

    /// Inspect a request and return a verdict.
    pub fn inspect(&self, ctx: &HttpRequestContext) -> WafVerdict {
        // If WAF is disabled, allow everything
        if self.mode == WafMode::Disabled {
            return WafVerdict {
                decision: WafDecision::Allow,
                matched_rules: Vec::new(),
                anomaly_score: 0,
            };
        }

        // Check exclusions: excluded IPs or paths bypass WAF inspection.
        let client_ip_str = ctx.remote_addr.to_string();
        if self.excluded_ips.iter().any(|ip| ip == &client_ip_str) {
            return WafVerdict {
                decision: WafDecision::Allow,
                matched_rules: Vec::new(),
                anomaly_score: 0,
            };
        }
        if self.excluded_paths.iter().any(|p| ctx.path.starts_with(p.as_str())) {
            return WafVerdict {
                decision: WafDecision::Allow,
                matched_rules: Vec::new(),
                anomaly_score: 0,
            };
        }

        let mut scorer = AnomalyScorer::new(self.anomaly_threshold);

        // Phase 1: Check request limits
        if let Some(verdict) = self.check_limits(ctx, &mut scorer) {
            return verdict;
        }

        // Phase 2: Run rule groups against targets
        self.evaluate_rules(ctx, &mut scorer);

        // Phase 3: Render verdict
        self.render_verdict(scorer)
    }

    /// Check request limits (body size, header count, etc.).
    fn check_limits(
        &self,
        ctx: &HttpRequestContext,
        scorer: &mut AnomalyScorer,
    ) -> Option<WafVerdict> {
        // Body size check
        if self.limits.max_body_size > 0 && ctx.body_size() > self.limits.max_body_size {
            scorer.add_match("LIMIT:body_size", 5);
            tracing::debug!(
                body_size = ctx.body_size(),
                max = self.limits.max_body_size,
                "request body exceeds limit",
            );
        }

        // Header count check
        if ctx.header_count() > self.limits.max_header_count {
            scorer.add_match("LIMIT:header_count", 5);
            tracing::debug!(
                count = ctx.header_count(),
                max = self.limits.max_header_count,
                "header count exceeds limit",
            );
        }

        // URI length check
        if ctx.uri.len() > self.limits.max_uri_length {
            scorer.add_match("LIMIT:uri_length", 5);
            tracing::debug!(
                len = ctx.uri.len(),
                max = self.limits.max_uri_length,
                "URI length exceeds limit",
            );
        }

        // Header value length check
        for (name, value) in &ctx.headers {
            if value.len() > self.limits.max_header_value_len {
                scorer.add_match(&format!("LIMIT:header_value_len:{}", name), 5);
                tracing::debug!(
                    header = %name,
                    len = value.len(),
                    max = self.limits.max_header_value_len,
                    "header value length exceeds limit",
                );
            }
        }

        // If any limits were exceeded and we're in blocking mode, short-circuit
        if scorer.is_anomalous() && self.mode == WafMode::Blocking {
            return Some(WafVerdict {
                decision: WafDecision::Block,
                matched_rules: scorer.matched_rule_ids.clone(),
                anomaly_score: scorer.current_score,
            });
        }

        None
    }

    /// Run all rule groups against the request.
    fn evaluate_rules(&self, ctx: &HttpRequestContext, scorer: &mut AnomalyScorer) {
        for group in &self.rule_groups {
            // Collect all target values to inspect
            let mut target_values = Vec::new();
            for target in &group.targets {
                target_values.extend(RuleMatcher::extract_targets(ctx, target));
            }

            // Apply transformations from the first rule (group shares transformations)
            let transformations = if let Some(first_rule) = group.rules.first() {
                &first_rule.transformations
            } else {
                continue;
            };

            // Test each target value against the regex set
            for value in &target_values {
                let transformed = RuleMatcher::apply_transformations(value, transformations);
                let matches = group.matches(&transformed);

                for idx in matches {
                    if let Some(rule) = group.rules.get(idx) {
                        let rule_id = format!("{}:{}", rule.id, rule.description);
                        scorer.add_match(&rule_id, rule.score);

                        tracing::debug!(
                            rule_id = rule.id,
                            description = %rule.description,
                            score = rule.score,
                            total_score = scorer.current_score,
                            "WAF rule matched",
                        );
                    }
                }
            }
        }
    }

    /// Convert the accumulated scoring into a final verdict.
    fn render_verdict(&self, scorer: AnomalyScorer) -> WafVerdict {
        if scorer.is_anomalous() {
            let decision = match self.mode {
                WafMode::Blocking => WafDecision::Block,
                WafMode::DetectionOnly => WafDecision::Log,
                WafMode::Disabled => WafDecision::Allow,
            };

            if decision == WafDecision::Block {
                tracing::info!(
                    anomaly_score = scorer.current_score,
                    threshold = self.anomaly_threshold,
                    matched_rules = ?scorer.matched_rule_ids,
                    "request blocked by WAF",
                );
            } else {
                tracing::info!(
                    anomaly_score = scorer.current_score,
                    threshold = self.anomaly_threshold,
                    matched_rules = ?scorer.matched_rule_ids,
                    "WAF detection (not blocking)",
                );
            }

            WafVerdict {
                decision,
                matched_rules: scorer.matched_rule_ids,
                anomaly_score: scorer.current_score,
            }
        } else {
            WafVerdict {
                decision: WafDecision::Allow,
                matched_rules: scorer.matched_rule_ids,
                anomaly_score: scorer.current_score,
            }
        }
    }
}
