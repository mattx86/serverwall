use bytes::Bytes;

/// IMAP command tag + command parsed from client input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapCommand {
    /// The client-assigned tag (e.g., "A001").
    pub tag: String,
    /// The command name (e.g., "LOGIN", "SELECT").
    pub command: String,
    /// The remaining arguments as a raw string.
    pub args: String,
}

/// IMAP server response.
#[derive(Debug, Clone)]
pub struct ImapResponse {
    /// Response tag ("*" for untagged, or the original command tag).
    pub tag: String,
    /// Status: OK, NO, BAD, or untagged response type.
    pub status: String,
    /// Response text.
    pub text: String,
}

impl ImapResponse {
    /// Create a tagged OK response.
    pub fn ok(tag: &str, text: impl Into<String>) -> Self {
        Self {
            tag: tag.to_string(),
            status: "OK".to_string(),
            text: text.into(),
        }
    }

    /// Create an untagged response.
    pub fn untagged(text: impl Into<String>) -> Self {
        Self {
            tag: "*".to_string(),
            status: String::new(),
            text: text.into(),
        }
    }

    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Bytes {
        let line = if self.status.is_empty() {
            format!("{} {}\r\n", self.tag, self.text)
        } else {
            format!("{} {} {}\r\n", self.tag, self.status, self.text)
        };
        Bytes::from(line)
    }
}

/// Parse a raw IMAP command line into an `ImapCommand`.
pub fn parse_command(line: &str) -> Option<ImapCommand> {
    let trimmed = line.trim();
    let mut parts = trimmed.splitn(3, ' ');
    let tag = parts.next()?.to_string();
    let command = parts.next()?.to_uppercase();
    let args = parts.next().unwrap_or("").to_string();
    Some(ImapCommand { tag, command, args })
}

/// Check if a line is a capability response.
pub fn is_capability_line(line: &str) -> bool {
    line.trim().starts_with("* CAPABILITY")
}

/// Inject an IMAP ID command for proxy identification.
pub fn build_id_command(tag: &str, proxy_name: &str) -> String {
    format!("{} ID (\"name\" \"{}\")\r\n", tag, proxy_name)
}
