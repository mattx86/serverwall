use bytes::Bytes;

/// SMTP command parsed from client input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpCommand {
    Ehlo(String),
    Helo(String),
    MailFrom(String),
    RcptTo(String),
    Data,
    Quit,
    Rset,
    Noop,
    StartTls,
    Auth(String),
    Xclient(String),
    Unknown(String),
}

/// SMTP server response.
#[derive(Debug, Clone)]
pub struct SmtpResponse {
    pub code: u16,
    pub enhanced_code: Option<String>,
    pub message: String,
}

impl SmtpResponse {
    /// Create a new SMTP response.
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            enhanced_code: None,
            message: message.into(),
        }
    }

    /// Serialize the response to wire format.
    pub fn to_bytes(&self) -> Bytes {
        let line = format!("{} {}\r\n", self.code, self.message);
        Bytes::from(line)
    }
}

/// Parse a raw SMTP command line into an `SmtpCommand`.
pub fn parse_command(line: &str) -> SmtpCommand {
    let trimmed = line.trim();
    let upper = trimmed.to_uppercase();

    if let Some(domain) = upper.strip_prefix("EHLO ") {
        SmtpCommand::Ehlo(domain.trim().to_string())
    } else if let Some(domain) = upper.strip_prefix("HELO ") {
        SmtpCommand::Helo(domain.trim().to_string())
    } else if upper.starts_with("MAIL FROM:") {
        let addr = trimmed["MAIL FROM:".len()..].trim().to_string();
        SmtpCommand::MailFrom(addr)
    } else if upper.starts_with("RCPT TO:") {
        let addr = trimmed["RCPT TO:".len()..].trim().to_string();
        SmtpCommand::RcptTo(addr)
    } else if upper == "DATA" {
        SmtpCommand::Data
    } else if upper == "QUIT" {
        SmtpCommand::Quit
    } else if upper == "RSET" {
        SmtpCommand::Rset
    } else if upper == "NOOP" {
        SmtpCommand::Noop
    } else if upper == "STARTTLS" {
        SmtpCommand::StartTls
    } else if let Some(rest) = upper.strip_prefix("AUTH ") {
        SmtpCommand::Auth(rest.trim().to_string())
    } else if let Some(rest) = upper.strip_prefix("XCLIENT ") {
        SmtpCommand::Xclient(rest.trim().to_string())
    } else {
        SmtpCommand::Unknown(trimmed.to_string())
    }
}
