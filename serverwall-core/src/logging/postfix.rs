use chrono::{DateTime, Utc};

/// A single log entry in Postfix-style syslog format.
///
/// Format:
/// ```text
/// <timestamp> <hostname> serverwall/smtp[<pid>]: <queue-id>: from=<sender>, to=<recipient>, relay=<backend>, spam_score=<N>, status=<status> (<detail>)
/// ```
pub struct PostfixLogEntry {
    /// Timestamp of the log entry
    pub timestamp: DateTime<Utc>,
    /// Hostname of the machine
    pub hostname: String,
    /// Service component name (e.g., "serverwall/smtp")
    pub service_name: String,
    /// Process ID
    pub pid: u32,
    /// Queue ID for the message
    pub queue_id: String,
    /// Sender email address
    pub sender: String,
    /// Recipient email address
    pub recipient: String,
    /// Backend relay server
    pub relay: String,
    /// Spam score
    pub spam_score: f64,
    /// Delivery status (e.g., "sent", "deferred", "bounced")
    pub status: String,
    /// Status detail message
    pub detail: String,
}

impl PostfixLogEntry {
    /// Format this entry as a Postfix-style log line.
    pub fn format(&self) -> String {
        let timestamp = self.timestamp.format("%b %e %H:%M:%S");
        format!(
            "{} {} {}[{}]: {}: from=<{}>, to=<{}>, relay={}, spam_score={}, status={} ({})",
            timestamp,
            self.hostname,
            self.service_name,
            self.pid,
            self.queue_id,
            self.sender,
            self.recipient,
            self.relay,
            self.spam_score,
            self.status,
            self.detail,
        )
    }
}

/// Formats log entries in Postfix-style syslog format (convenience wrapper).
pub struct PostfixLogFormatter {
    /// The service name to include in log lines (e.g., "serverwall/smtp").
    service_name: String,
}

impl PostfixLogFormatter {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    /// Format a log line in Postfix style.
    pub fn format(&self, queue_id: &str, message: &str) -> String {
        let now = Utc::now().format("%b %e %H:%M:%S");
        format!("{} {}: {}: {}", now, self.service_name, queue_id, message)
    }
}

impl Default for PostfixLogFormatter {
    fn default() -> Self {
        Self::new("serverwall/smtp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_postfix_log_entry_format() {
        let entry = PostfixLogEntry {
            timestamp: Utc.with_ymd_and_hms(2026, 3, 6, 19, 30, 0).unwrap(),
            hostname: "mail.example.com".to_string(),
            service_name: "serverwall/smtp".to_string(),
            pid: 12345,
            queue_id: "ABC123DEF".to_string(),
            sender: "alice@example.com".to_string(),
            recipient: "bob@example.org".to_string(),
            relay: "backend1.example.com".to_string(),
            spam_score: 2.5,
            status: "sent".to_string(),
            detail: "250 2.0.0 Ok: queued".to_string(),
        };

        let line = entry.format();
        assert!(line.contains("mail.example.com"));
        assert!(line.contains("serverwall/smtp[12345]"));
        assert!(line.contains("ABC123DEF"));
        assert!(line.contains("from=<alice@example.com>"));
        assert!(line.contains("to=<bob@example.org>"));
        assert!(line.contains("relay=backend1.example.com"));
        assert!(line.contains("spam_score=2.5"));
        assert!(line.contains("status=sent"));
        assert!(line.contains("(250 2.0.0 Ok: queued)"));
    }

    #[test]
    fn test_postfix_log_formatter() {
        let formatter = PostfixLogFormatter::new("serverwall/smtp");
        let line = formatter.format("QUEUEID1", "from=<test@test.com>, status=sent");
        assert!(line.contains("serverwall/smtp: QUEUEID1:"));
        assert!(line.contains("from=<test@test.com>, status=sent"));
    }
}
