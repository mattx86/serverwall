use crate::rules::rule_set::{RuleTarget, WafRule};

/// Detects cross-site scripting (XSS) patterns in request data.
pub struct XssDetector;

impl XssDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, _input: &str) -> bool {
        false
    }
}

/// Return XSS detection rules at various paranoia levels.
pub fn xss_rules() -> Vec<WafRule> {
    let targets = vec![
        RuleTarget::QueryString,
        RuleTarget::RequestBody,
        RuleTarget::RequestUri,
        RuleTarget::Cookies,
    ];

    vec![
        // Paranoia Level 1
        WafRule::regex(
            942100,
            "XSS: <script> tag injection",
            targets.clone(),
            r"(?i)<\s*script[^>]*>",
            1, 5, 1,
        ),
        WafRule::regex(
            942110,
            "XSS: javascript: protocol handler",
            targets.clone(),
            r"(?i)javascript\s*:",
            1, 5, 1,
        ),
        WafRule::regex(
            942120,
            "XSS: on-event handler attributes",
            targets.clone(),
            r"(?i)\bon(?:error|load|click|mouse(?:over|out|down|up)|focus|blur|change|submit|key(?:down|up|press)|unload)\s*=",
            1, 5, 1,
        ),
        WafRule::regex(
            942130,
            "XSS: <iframe>/<object>/<embed> injection",
            targets.clone(),
            r"(?i)<\s*(?:iframe|object|embed|applet|form|base)\b",
            1, 5, 1,
        ),
        WafRule::regex(
            942140,
            "XSS: data: URI with script content",
            targets.clone(),
            r"(?i)data\s*:\s*(?:text/html|application/xhtml)",
            2, 4, 1,
        ),
        // Paranoia Level 2
        WafRule::regex(
            942200,
            "XSS: SVG onload/animate attack",
            targets.clone(),
            r"(?i)<\s*svg[^>]*\bon(?:load|error)\s*=",
            2, 4, 2,
        ),
        WafRule::regex(
            942210,
            "XSS: HTML entity encoding bypass",
            targets.clone(),
            r"(?i)(?:&#(?:x0*(?:6[1-9a-f]|7[0-9a])|0*(?:9[7-9]|1[01][0-9]|12[0-2]))\s*;?)",
            3, 3, 2,
        ),
        WafRule::regex(
            942220,
            "XSS: expression() CSS function",
            targets.clone(),
            r"(?i)(?:expression|behavior)\s*\(",
            2, 4, 2,
        ),
        WafRule::regex(
            942230,
            "XSS: vbscript: protocol handler",
            targets.clone(),
            r"(?i)vbscript\s*:",
            1, 5, 2,
        ),
        WafRule::regex(
            942240,
            "XSS: <img> tag with event handler",
            targets.clone(),
            r"(?i)<\s*img[^>]+\bon(?:error|load)\s*=",
            2, 4, 2,
        ),
        // Paranoia Level 3
        WafRule::regex(
            942300,
            "XSS: alert/confirm/prompt/eval function calls",
            targets.clone(),
            r"(?i)(?:alert|confirm|prompt|eval)\s*\(",
            3, 3, 3,
        ),
        WafRule::regex(
            942310,
            "XSS: document.cookie/document.write access",
            targets.clone(),
            r"(?i)document\s*\.\s*(?:cookie|write|location|domain)",
            3, 3, 3,
        ),
        WafRule::regex(
            942320,
            "XSS: innerHTML/outerHTML DOM manipulation",
            targets.clone(),
            r"(?i)\.(?:innerHTML|outerHTML|insertAdjacentHTML|write|writeln)\s*[=(]",
            3, 3, 3,
        ),
    ]
}
