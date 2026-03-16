use serverwall_core::config::schema::OutboundPolicyConfig;

/// Outbound content policy checks: dangerous attachments, phishing URLs.
pub struct OutboundContentPolicy {
    /// File extensions to block (e.g. exe, bat, scr).
    dangerous_extensions: Vec<String>,
    /// Whether to scan message bodies for suspicious URLs.
    check_urls: bool,
    /// Maximum message size in bytes.
    max_message_size: usize,
}

impl OutboundContentPolicy {
    /// Build from the outbound policy configuration.
    pub fn new(config: &OutboundPolicyConfig) -> Self {
        let dangerous_extensions = if config.block_dangerous_attachments {
            vec![
                "exe", "scr", "bat", "cmd", "ps1", "vbs", "js", "msi", "dll", "hta",
                "pif", "com", "cpl", "wsf", "wsh",
            ]
            .into_iter()
            .map(String::from)
            .collect()
        } else {
            Vec::new()
        };

        Self {
            dangerous_extensions,
            check_urls: config.check_urls,
            max_message_size: config.max_message_size,
        }
    }

    /// Check the outbound message content.
    /// Returns `Ok(())` if clean, `Err(reason)` if policy violated.
    pub fn check(&self, message: &[u8]) -> Result<(), String> {
        // Size check
        if message.len() > self.max_message_size {
            return Err(format!(
                "message size {} exceeds limit {}",
                message.len(),
                self.max_message_size
            ));
        }

        let msg_str = String::from_utf8_lossy(message);

        // Dangerous attachment check: look for Content-Disposition/Content-Type
        // with dangerous file extensions
        if !self.dangerous_extensions.is_empty() {
            // Check for filename= or name= in MIME headers
            for line in msg_str.lines() {
                let lower = line.to_lowercase();
                if lower.contains("filename=") || lower.contains("name=") {
                    for ext in &self.dangerous_extensions {
                        let pattern = format!(".{ext}");
                        if lower.contains(&pattern) {
                            return Err(format!(
                                "dangerous attachment type blocked: .{ext}"
                            ));
                        }
                    }
                }
            }
        }

        // Basic phishing URL check
        if self.check_urls {
            // Look for known phishing patterns in URLs
            let suspicious_patterns = [
                "data:text/html",
                "javascript:",
                ".tk/",
                ".ml/",
                "bit.ly/",
            ];
            for pattern in &suspicious_patterns {
                if msg_str.contains(pattern) {
                    return Err(format!(
                        "suspicious URL pattern detected: {pattern}"
                    ));
                }
            }
        }

        Ok(())
    }
}
