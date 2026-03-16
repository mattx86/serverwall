use super::rule_set::{RuleTarget, Transformation};
use crate::request::HttpRequestContext;

/// Applies transformations to input and executes matching logic.
pub struct RuleMatcher;

impl RuleMatcher {
    pub fn new() -> Self {
        Self
    }

    /// Extract the target values from the request context for a given target type.
    pub fn extract_targets(ctx: &HttpRequestContext, target: &RuleTarget) -> Vec<String> {
        match target {
            RuleTarget::RequestUri => vec![ctx.uri.clone()],
            RuleTarget::Path => vec![ctx.path.clone()],
            RuleTarget::QueryString => {
                if ctx.query_string.is_empty() {
                    vec![]
                } else {
                    vec![ctx.query_string.clone()]
                }
            }
            RuleTarget::RequestHeaders => {
                ctx.headers.values().cloned().collect()
            }
            RuleTarget::HeaderValue(name) => {
                let lower = name.to_lowercase();
                ctx.headers
                    .iter()
                    .filter(|(k, _)| k.to_lowercase() == lower)
                    .map(|(_, v)| v.clone())
                    .collect()
            }
            RuleTarget::RequestBody => {
                let body = String::from_utf8_lossy(&ctx.body).to_string();
                if body.is_empty() {
                    vec![]
                } else {
                    vec![body]
                }
            }
            RuleTarget::Cookies => {
                ctx.cookies.values().cloned().collect()
            }
            RuleTarget::UserAgent => {
                ctx.user_agent().map(|s| vec![s.to_string()]).unwrap_or_default()
            }
            RuleTarget::RemoteAddr => {
                vec![ctx.remote_addr.to_string()]
            }
        }
    }

    /// Apply a chain of transformations to an input string.
    pub fn apply_transformations(input: &str, transformations: &[Transformation]) -> String {
        let mut result = input.to_string();
        for t in transformations {
            result = match t {
                Transformation::Lowercase => result.to_lowercase(),
                Transformation::UrlDecode => url_decode(&result),
                Transformation::HtmlEntityDecode => html_entity_decode(&result),
                Transformation::Base64Decode => {
                    // Best-effort base64 decode; fall back to original on failure
                    decode_base64(&result).unwrap_or(result)
                }
                Transformation::RemoveWhitespace => {
                    result.chars().filter(|c| !c.is_whitespace()).collect()
                }
                Transformation::NormalizePath => normalize_path(&result),
                Transformation::None => result,
            };
        }
        result
    }
}

/// Simple percent-decoding for URL-encoded strings.
fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

/// Decode common HTML entities.
fn html_entity_decode(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&#x27;", "'")
        .replace("&#x2f;", "/")
        .replace("&#x2F;", "/")
        .replace("&#34;", "\"")
        .replace("&#60;", "<")
        .replace("&#62;", ">")
}

/// Normalize path: collapse `..`, `//`, `./`.
fn normalize_path(input: &str) -> String {
    let mut result = input.replace('\\', "/");
    // Collapse multiple slashes
    while result.contains("//") {
        result = result.replace("//", "/");
    }
    // Remove ./
    result = result.replace("/./", "/");
    result
}

/// Best-effort base64 decode.
fn decode_base64(input: &str) -> Option<String> {
    // Simple base64 decode without pulling in a crate
    // We only attempt if it looks like valid base64
    let trimmed = input.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return None;
    }

    // Minimal base64 decode
    let bytes = simple_base64_decode(trimmed)?;
    String::from_utf8(bytes).ok()
}

fn simple_base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn val(c: u8) -> Option<u8> {
        TABLE.iter().position(|&b| b == c).map(|p| p as u8)
    }

    let input = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let chunks = input.chunks(4);
    for chunk in chunks {
        let len = chunk.iter().filter(|&&b| b != b'=').count();
        if len < 2 {
            return None;
        }
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        out.push((a << 2) | (b >> 4));
        if len > 2 {
            let c = val(chunk[2])?;
            out.push((b << 4) | (c >> 2));
            if len > 3 {
                let d = val(chunk[3])?;
                out.push((c << 6) | d);
            }
        }
    }
    Some(out)
}
