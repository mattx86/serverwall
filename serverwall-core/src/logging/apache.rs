use std::net::IpAddr;

use chrono::{DateTime, Utc};

/// A single entry in Apache Combined Log Format.
///
/// Format: `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`
///
/// Example:
/// ```text
/// 10.0.0.1 - - [06/Mar/2026:19:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"
/// ```
pub struct ApacheLogEntry {
    /// Remote host IP address (%h)
    pub client_ip: IpAddr,
    /// Remote logname (%l) - always "-"
    pub ident: String,
    /// Remote user (%u)
    pub user: String,
    /// Timestamp (%t)
    pub timestamp: DateTime<Utc>,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// HTTP protocol version
    pub protocol: String,
    /// Response status code (%>s)
    pub status: u16,
    /// Response body size in bytes (%b)
    pub bytes: u64,
    /// Referer header (%{Referer}i)
    pub referer: Option<String>,
    /// User-Agent header (%{User-Agent}i)
    pub user_agent: Option<String>,
}

impl ApacheLogEntry {
    /// Format this entry as an Apache Combined Log Format line.
    pub fn format(&self) -> String {
        let timestamp = self.timestamp.format("%d/%b/%Y:%H:%M:%S %z");
        let referer = self.referer.as_deref().unwrap_or("-");
        let user_agent = self.user_agent.as_deref().unwrap_or("-");

        format!(
            "{} {} {} [{}] \"{} {} {}\" {} {} \"{}\" \"{}\"",
            self.client_ip,
            self.ident,
            self.user,
            timestamp,
            self.method,
            self.path,
            self.protocol,
            self.status,
            self.bytes,
            referer,
            user_agent,
        )
    }
}

/// Formats log entries in Apache Combined Log Format (convenience wrapper).
pub struct ApacheLogFormatter;

impl ApacheLogFormatter {
    pub fn new() -> Self {
        Self
    }

    /// Format a single log line using provided fields.
    pub fn format(
        &self,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        status: u16,
        bytes: u64,
        referer: Option<&str>,
        user_agent: Option<&str>,
    ) -> String {
        let entry = ApacheLogEntry {
            client_ip,
            ident: "-".to_string(),
            user: "-".to_string(),
            timestamp: Utc::now(),
            method: method.to_string(),
            path: path.to_string(),
            protocol: "HTTP/1.1".to_string(),
            status,
            bytes,
            referer: referer.map(String::from),
            user_agent: user_agent.map(String::from),
        };
        entry.format()
    }
}

impl Default for ApacheLogFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_apache_log_entry_format() {
        let entry = ApacheLogEntry {
            client_ip: "10.0.0.1".parse().unwrap(),
            ident: "-".to_string(),
            user: "-".to_string(),
            timestamp: Utc.with_ymd_and_hms(2026, 3, 6, 19, 30, 0).unwrap(),
            method: "GET".to_string(),
            path: "/index.html".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            bytes: 1234,
            referer: Some("https://example.com".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        };

        let line = entry.format();
        assert_eq!(
            line,
            "10.0.0.1 - - [06/Mar/2026:19:30:00 +0000] \"GET /index.html HTTP/1.1\" 200 1234 \"https://example.com\" \"Mozilla/5.0\""
        );
    }

    #[test]
    fn test_apache_log_entry_format_no_referer_no_ua() {
        let entry = ApacheLogEntry {
            client_ip: "192.168.1.100".parse().unwrap(),
            ident: "-".to_string(),
            user: "-".to_string(),
            timestamp: Utc.with_ymd_and_hms(2026, 1, 15, 8, 0, 0).unwrap(),
            method: "POST".to_string(),
            path: "/api/data".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status: 201,
            bytes: 56,
            referer: None,
            user_agent: None,
        };

        let line = entry.format();
        assert!(line.contains("192.168.1.100 - -"));
        assert!(line.contains("\"POST /api/data HTTP/1.1\" 201 56"));
        assert!(line.contains("\"-\" \"-\""));
    }
}
