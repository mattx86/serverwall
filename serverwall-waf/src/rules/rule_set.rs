use regex::RegexSet;

/// Which part of the request to inspect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTarget {
    RequestUri,
    Path,
    QueryString,
    RequestHeaders,
    HeaderValue(String),
    RequestBody,
    Cookies,
    UserAgent,
    RemoteAddr,
}

/// The comparison operator for a rule condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOperator {
    Regex,
    Contains,
    Equals,
    StartsWith,
    EndsWith,
    GreaterThan,
    LessThan,
    DetectSqli,
    DetectXss,
}

/// A transformation to apply to the target value before matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transformation {
    Lowercase,
    UrlDecode,
    HtmlEntityDecode,
    Base64Decode,
    RemoveWhitespace,
    NormalizePath,
    None,
}

/// Severity levels aligned with OWASP CRS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical = 1,
    Error = 2,
    Warning = 3,
    Notice = 4,
}

impl Severity {
    /// Default anomaly score for this severity level.
    pub fn default_score(&self) -> u32 {
        match self {
            Severity::Critical => 5,
            Severity::Error => 4,
            Severity::Warning => 3,
            Severity::Notice => 2,
        }
    }
}

/// A single WAF rule definition.
#[derive(Debug, Clone)]
pub struct WafRule {
    pub id: u32,
    pub description: String,
    pub targets: Vec<RuleTarget>,
    pub operator: RuleOperator,
    pub pattern: String,
    pub transformations: Vec<Transformation>,
    pub severity: u8,
    pub score: u32,
    /// Minimum paranoia level required to activate this rule.
    pub paranoia_level: u8,
}

impl WafRule {
    /// Helper to create a regex-based rule with common defaults.
    pub fn regex(
        id: u32,
        description: &str,
        targets: Vec<RuleTarget>,
        pattern: &str,
        severity: u8,
        score: u32,
        paranoia_level: u8,
    ) -> Self {
        Self {
            id,
            description: description.to_string(),
            targets,
            operator: RuleOperator::Regex,
            pattern: pattern.to_string(),
            transformations: vec![Transformation::Lowercase, Transformation::UrlDecode],
            severity,
            score,
            paranoia_level,
        }
    }
}

/// A group of rules pre-compiled into a RegexSet for efficient batch matching.
///
/// All rules in a group share the same targets. The `RegexSet` allows testing
/// all patterns in one pass.
#[derive(Debug)]
pub struct CompiledRuleGroup {
    /// The compiled regex set for batch matching.
    pub regex_set: RegexSet,
    /// The original rules, indexed to match the RegexSet.
    pub rules: Vec<WafRule>,
    /// The targets this group inspects.
    pub targets: Vec<RuleTarget>,
}

impl CompiledRuleGroup {
    /// Compile a set of regex-based WAF rules into a single RegexSet.
    ///
    /// Rules that fail to compile are logged and skipped.
    pub fn compile(rules: Vec<WafRule>) -> Option<Self> {
        if rules.is_empty() {
            return None;
        }

        let targets = rules[0].targets.clone();

        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();

        match RegexSet::new(&patterns) {
            Ok(regex_set) => Some(Self {
                regex_set,
                rules,
                targets,
            }),
            Err(e) => {
                tracing::warn!(error = %e, "failed to compile WAF rule group regex set");
                // Try compiling rules one by one, skipping broken ones
                let mut valid_rules = Vec::new();
                let mut valid_patterns = Vec::new();
                for rule in rules {
                    if regex::Regex::new(&rule.pattern).is_ok() {
                        valid_patterns.push(rule.pattern.clone());
                        valid_rules.push(rule);
                    } else {
                        tracing::warn!(
                            rule_id = rule.id,
                            pattern = %rule.pattern,
                            "skipping rule with invalid regex",
                        );
                    }
                }
                if valid_rules.is_empty() {
                    return None;
                }
                let regex_set = RegexSet::new(&valid_patterns).ok()?;
                Some(Self {
                    regex_set,
                    rules: valid_rules,
                    targets,
                })
            }
        }
    }

    /// Test an input string against all patterns, returning indices of matches.
    pub fn matches(&self, input: &str) -> Vec<usize> {
        self.regex_set.matches(input).into_iter().collect()
    }
}
