/// The final WAF decision for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafDecision {
    /// Allow the request to proceed.
    Allow,
    /// Block the request and return an error response.
    Block,
    /// Allow the request but log the match.
    Log,
    /// Redirect the request to a different URL.
    Redirect(String),
    /// Present a challenge (e.g., CAPTCHA) before allowing.
    Challenge,
}

impl WafDecision {
    /// Returns the HTTP status code for a blocked request.
    pub fn status_code(&self) -> u16 {
        match self {
            WafDecision::Allow => 200,
            WafDecision::Block => 403,
            WafDecision::Log => 200,
            WafDecision::Redirect(_) => 302,
            WafDecision::Challenge => 429,
        }
    }

    /// Returns true if the request should be blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self, WafDecision::Block)
    }
}
