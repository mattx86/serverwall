pub mod rate_limit;
pub mod content_policy;
pub mod spf_alignment;
pub mod recipient_limit;

pub use rate_limit::OutboundRateLimit;
pub use content_policy::OutboundContentPolicy;
pub use spf_alignment::SpfAlignmentCheck;
pub use recipient_limit::RecipientLimit;

/// Combined outbound policy checker.
pub struct OutboundPolicyChecker {
    pub rate_limit: OutboundRateLimit,
    pub content_policy: OutboundContentPolicy,
    pub spf_alignment: SpfAlignmentCheck,
    pub recipient_limit: RecipientLimit,
}

impl OutboundPolicyChecker {
    /// Run all outbound policy checks.
    /// Returns `Ok(())` if all pass, `Err(reason)` on first violation.
    pub fn check(
        &self,
        sender_domain: &str,
        recipient_count: usize,
        message: &[u8],
    ) -> Result<(), String> {
        self.spf_alignment.check(sender_domain)?;
        self.recipient_limit.check(recipient_count)?;
        self.rate_limit.check(sender_domain)?;
        self.content_policy.check(message)?;
        Ok(())
    }
}
