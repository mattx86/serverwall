/// Verify that the sender domain is in the allowed_sender_domains list.
/// This is a simple allowlist check, not a full SPF evaluation.
pub struct SpfAlignmentCheck {
    allowed_domains: Vec<String>,
}

impl SpfAlignmentCheck {
    /// Create with the list of allowed sender domains.
    pub fn new(allowed_domains: Vec<String>) -> Self {
        Self {
            allowed_domains: allowed_domains
                .into_iter()
                .map(|d| d.to_lowercase())
                .collect(),
        }
    }

    /// Check whether `sender_domain` is allowed.
    /// If the allowed list is empty, all domains are permitted.
    /// Returns `Ok(())` if allowed, `Err(reason)` if not.
    pub fn check(&self, sender_domain: &str) -> Result<(), String> {
        if self.allowed_domains.is_empty() {
            return Ok(());
        }

        let domain_lower = sender_domain.to_lowercase();
        if self.allowed_domains.contains(&domain_lower) {
            Ok(())
        } else {
            Err(format!(
                "sender domain '{sender_domain}' is not in allowed_sender_domains"
            ))
        }
    }
}
