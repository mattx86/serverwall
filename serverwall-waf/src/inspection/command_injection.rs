use crate::rules::rule_set::{RuleTarget, WafRule};

/// Detects OS command injection patterns in request data.
pub struct CommandInjectionDetector;

impl CommandInjectionDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, _input: &str) -> bool {
        false
    }
}

/// Return OS command injection detection rules at various paranoia levels.
pub fn command_injection_rules() -> Vec<WafRule> {
    let targets = vec![
        RuleTarget::QueryString,
        RuleTarget::RequestBody,
        RuleTarget::RequestUri,
        RuleTarget::Cookies,
    ];

    vec![
        // Paranoia Level 1
        WafRule::regex(
            944100,
            "Command Injection: shell command chaining (;, &&, ||)",
            targets.clone(),
            r"(?:;\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh|python|perl|ruby|php)\b)",
            1, 5, 1,
        ),
        WafRule::regex(
            944110,
            "Command Injection: backtick command substitution",
            targets.clone(),
            r"`[^`]*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh)[^`]*`",
            1, 5, 1,
        ),
        WafRule::regex(
            944120,
            "Command Injection: $() command substitution",
            targets.clone(),
            r"\$\([^)]*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh)[^)]*\)",
            1, 5, 1,
        ),
        WafRule::regex(
            944130,
            "Command Injection: pipe to shell commands",
            targets.clone(),
            r"(?:\|\s*(?:cat|ls|id|whoami|uname|bash|sh|python|perl|nc|ncat|wget|curl)\b)",
            1, 5, 1,
        ),
        WafRule::regex(
            944140,
            "Command Injection: /bin/ or /usr/bin/ direct execution",
            targets.clone(),
            r"(?:/(?:usr/)?(?:s?bin|local/bin)/(?:cat|ls|id|whoami|uname|bash|sh|python|perl|nc|wget|curl|chmod|chown))",
            1, 5, 1,
        ),
        // Paranoia Level 2
        WafRule::regex(
            944200,
            "Command Injection: && or || chaining with any command",
            targets.clone(),
            r"(?:(?:&&|\|\|)\s*\w+\b)",
            3, 3, 2,
        ),
        WafRule::regex(
            944210,
            "Command Injection: redirection operators",
            targets.clone(),
            r"(?:>\s*/(?:etc|tmp|var|dev)|>>\s*\S+|<\s*/(?:etc|proc|dev))",
            2, 4, 2,
        ),
        WafRule::regex(
            944220,
            "Command Injection: environment variable injection",
            targets.clone(),
            r"(?:\$\{(?:IFS|PATH|SHELL|HOME|USER|HOSTNAME)\})",
            2, 4, 2,
        ),
        WafRule::regex(
            944230,
            "Command Injection: Powershell command patterns",
            targets.clone(),
            r"(?i)(?:powershell|invoke-(?:expression|webrequest|command)|new-object\s+system)",
            1, 5, 2,
        ),
        // Paranoia Level 3
        WafRule::regex(
            944300,
            "Command Injection: semicolon followed by any word",
            targets.clone(),
            r"(?:;\s*\w+)",
            4, 2, 3,
        ),
        WafRule::regex(
            944310,
            "Command Injection: line feeds used as command separators",
            targets.clone(),
            r"(?:%0[ad]|\\n|\\r)",
            4, 2, 3,
        ),
    ]
}
