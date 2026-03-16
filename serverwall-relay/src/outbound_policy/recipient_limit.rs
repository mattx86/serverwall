/// Limits the number of recipients per message.
pub struct RecipientLimit {
    max_recipients: usize,
}

impl RecipientLimit {
    pub fn new(max_recipients: usize) -> Self {
        Self { max_recipients }
    }

    /// Check whether the recipient count is within limits.
    /// Returns `Ok(())` if allowed, `Err(reason)` if exceeded.
    pub fn check(&self, recipient_count: usize) -> Result<(), String> {
        if recipient_count > self.max_recipients {
            Err(format!(
                "too many recipients: {recipient_count} exceeds limit of {}",
                self.max_recipients
            ))
        } else {
            Ok(())
        }
    }
}
