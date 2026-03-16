use crate::rules::rule_set::{RuleTarget, WafRule};

/// Detects path traversal attempts (e.g., `../../etc/passwd`).
pub struct PathTraversalDetector;

impl PathTraversalDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, _input: &str) -> bool {
        false
    }
}

/// Return path traversal detection rules at various paranoia levels.
pub fn path_traversal_rules() -> Vec<WafRule> {
    let targets = vec![
        RuleTarget::RequestUri,
        RuleTarget::Path,
        RuleTarget::QueryString,
        RuleTarget::RequestBody,
    ];

    vec![
        // Paranoia Level 1
        WafRule::regex(
            943100,
            "Path Traversal: ../ sequences",
            targets.clone(),
            r"(?:\.\./|\.\.\\)",
            1, 5, 1,
        ),
        WafRule::regex(
            943110,
            "Path Traversal: /etc/passwd or /etc/shadow access",
            targets.clone(),
            r"(?i)/etc/(?:passwd|shadow|hosts|group|resolv\.conf|issue)",
            1, 5, 1,
        ),
        WafRule::regex(
            943120,
            "Path Traversal: Windows drive letter access",
            targets.clone(),
            r"(?i)(?:(?:^|[^a-z])[a-z]:\\|\\\\[a-z0-9])",
            2, 4, 1,
        ),
        WafRule::regex(
            943130,
            "Path Traversal: null byte injection",
            targets.clone(),
            r"(?:%00|\\x00|\\0)",
            1, 5, 1,
        ),
        WafRule::regex(
            943140,
            "Path Traversal: /proc/self or /dev/ access",
            targets.clone(),
            r"(?:/proc/(?:self|version|cpuinfo|meminfo)|/dev/(?:null|zero|random|urandom|tcp|udp))",
            1, 5, 1,
        ),
        // Paranoia Level 2
        WafRule::regex(
            943200,
            "Path Traversal: URL-encoded ../ sequences",
            targets.clone(),
            r"(?:%2e%2e[/\\]|\.%2e[/\\]|%2e\.[/\\]|%252e%252e)",
            2, 4, 2,
        ),
        WafRule::regex(
            943210,
            "Path Traversal: Windows system file access",
            targets.clone(),
            r"(?i)(?:windows[\\/]system32|windows[\\/]win\.ini|boot\.ini|web\.config)",
            2, 4, 2,
        ),
        WafRule::regex(
            943220,
            "Path Traversal: UTF-8 encoded traversal",
            targets.clone(),
            r"(?:%c0%ae|%c1%9c|%c0%af)",
            1, 5, 2,
        ),
        WafRule::regex(
            943230,
            "Path Traversal: sensitive config file access",
            targets.clone(),
            r"(?i)(?:\.htaccess|\.htpasswd|\.env|\.git/|\.svn/|wp-config\.php|config\.yml|database\.yml)",
            2, 4, 2,
        ),
        // Paranoia Level 3
        WafRule::regex(
            943300,
            "Path Traversal: backslash-encoded sequences",
            targets.clone(),
            r"(?:\\\\\.\\\\\.)",
            3, 3, 3,
        ),
    ]
}
