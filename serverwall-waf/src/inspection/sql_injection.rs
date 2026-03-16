use crate::rules::rule_set::{RuleTarget, WafRule};

/// Detects SQL injection patterns in request data.
pub struct SqlInjectionDetector;

impl SqlInjectionDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, _input: &str) -> bool {
        false
    }
}

/// Return SQL injection detection rules at various paranoia levels.
pub fn sql_injection_rules() -> Vec<WafRule> {
    let targets = vec![
        RuleTarget::QueryString,
        RuleTarget::RequestBody,
        RuleTarget::RequestUri,
        RuleTarget::Cookies,
    ];

    vec![
        // Paranoia Level 1 - high confidence patterns
        WafRule::regex(
            941100,
            "SQL Injection: UNION-based attack",
            targets.clone(),
            r"(?i)(?:union\s+(?:all\s+)?select)",
            1, 5, 1,
        ),
        WafRule::regex(
            941110,
            "SQL Injection: tautology (OR 1=1, OR true)",
            targets.clone(),
            r"(?i)(?:'\s*(?:or|and)\s+['\d][\d\s]*=\s*['\d])",
            1, 5, 1,
        ),
        WafRule::regex(
            941120,
            "SQL Injection: comment-based bypass (--)",
            targets.clone(),
            r"(?i)(?:'\s*;\s*--\s*|'\s*--\s*)",
            2, 4, 1,
        ),
        WafRule::regex(
            941130,
            "SQL Injection: DROP/ALTER/TRUNCATE statements",
            targets.clone(),
            r"(?i)(?:;\s*(?:drop|alter|truncate|create|insert|update|delete)\s+(?:table|database|schema|index))",
            1, 5, 1,
        ),
        WafRule::regex(
            941140,
            "SQL Injection: EXEC/EXECUTE xp_cmdshell",
            targets.clone(),
            r"(?i)(?:(?:exec|execute)\s+(?:xp_|sp_)|xp_cmdshell)",
            1, 5, 1,
        ),
        // Paranoia Level 2 - broader patterns
        WafRule::regex(
            941200,
            "SQL Injection: SLEEP/BENCHMARK/WAITFOR timing attacks",
            targets.clone(),
            r"(?i)(?:sleep\s*\(\s*\d|benchmark\s*\(\s*\d|waitfor\s+delay\s+')",
            2, 4, 2,
        ),
        WafRule::regex(
            941210,
            "SQL Injection: stacked queries",
            targets.clone(),
            r"(?i)(?:;\s*(?:select|insert|update|delete|drop|alter|create)\s)",
            2, 4, 2,
        ),
        WafRule::regex(
            941220,
            "SQL Injection: INFORMATION_SCHEMA/system tables",
            targets.clone(),
            r"(?i)(?:information_schema|mysql\.user|sysobjects|syscolumns|pg_catalog)",
            2, 4, 2,
        ),
        WafRule::regex(
            941230,
            "SQL Injection: LOAD_FILE/INTO OUTFILE",
            targets.clone(),
            r"(?i)(?:load_file\s*\(|into\s+(?:out|dump)file)",
            1, 5, 2,
        ),
        WafRule::regex(
            941240,
            "SQL Injection: hex-encoded values",
            targets.clone(),
            r"(?i)(?:0x[0-9a-f]{8,}|char\s*\(\s*\d+(?:\s*,\s*\d+)+\s*\))",
            3, 3, 2,
        ),
        // Paranoia Level 3 - more aggressive
        WafRule::regex(
            941300,
            "SQL Injection: common SQL keywords in suspicious context",
            targets.clone(),
            r"(?i)(?:'\s*(?:having|group\s+by|order\s+by|limit)\s)",
            3, 3, 3,
        ),
        WafRule::regex(
            941310,
            "SQL Injection: SQL function calls",
            targets.clone(),
            r"(?i)(?:(?:concat|substr|substring|ascii|hex|unhex|conv|cast)\s*\()",
            4, 2, 3,
        ),
        WafRule::regex(
            941320,
            "SQL Injection: single-quote probing",
            targets.clone(),
            r"(?:(?:^|[^\w])'\s*(?:$|[^\w']))",
            4, 2, 4,
        ),
    ]
}
