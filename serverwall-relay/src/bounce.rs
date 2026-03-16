use chrono::Utc;

use crate::queue::message::Envelope;

/// Generates DSN (Delivery Status Notification) bounce messages per RFC 3464.
pub struct BounceGenerator {
    /// The sender address for bounces (default: MAILER-DAEMON).
    bounce_sender: String,
    /// Whether to include original message headers in the bounce.
    include_original_headers: bool,
}

impl BounceGenerator {
    /// Create a bounce generator with a custom sender address.
    pub fn new(bounce_sender: Option<String>, include_original_headers: bool) -> Self {
        Self {
            bounce_sender: bounce_sender.unwrap_or_else(|| String::new()), // empty = null sender
            include_original_headers,
        }
    }

    /// Generate a DSN bounce message.
    ///
    /// Returns `(envelope, message_bytes)` for the bounce, or `None` if the
    /// original sender is the null sender (to prevent bounce loops).
    pub fn generate(
        &self,
        original_envelope: &Envelope,
        error_message: &str,
        original_message: &[u8],
    ) -> Option<(Envelope, Vec<u8>)> {
        // Never bounce a bounce (null sender or MAILER-DAEMON)
        if original_envelope.mail_from.is_empty()
            || original_envelope.mail_from.eq_ignore_ascii_case("MAILER-DAEMON")
            || original_envelope.mail_from == "<>"
        {
            tracing::debug!("not generating bounce for null sender");
            return None;
        }

        let now = Utc::now();
        let message_id = format!(
            "<bounce-{}-{}@localhost>",
            now.timestamp(),
            uuid::Uuid::new_v4().as_simple()
        );
        let date = now.to_rfc2822();

        let original_headers = if self.include_original_headers {
            extract_headers(original_message)
        } else {
            String::new()
        };

        let recipients_report: String = original_envelope
            .rcpt_to
            .iter()
            .map(|rcpt| {
                format!(
                    concat!(
                        "Final-Recipient: rfc822;{rcpt}\r\n",
                        "Action: failed\r\n",
                        "Status: 5.0.0\r\n",
                        "Diagnostic-Code: smtp; {error}\r\n",
                    ),
                    rcpt = rcpt,
                    error = error_message,
                )
            })
            .collect::<Vec<_>>()
            .join("\r\n");

        let boundary = format!("=_bounce_{}", now.timestamp_millis());

        let body = format!(
            concat!(
                "From: MAILER-DAEMON <{sender}>\r\n",
                "To: <{original_sender}>\r\n",
                "Date: {date}\r\n",
                "Message-ID: {message_id}\r\n",
                "Subject: Delivery Status Notification (Failure)\r\n",
                "MIME-Version: 1.0\r\n",
                "Content-Type: multipart/report; report-type=delivery-status;\r\n",
                "    boundary=\"{boundary}\"\r\n",
                "\r\n",
                "--{boundary}\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n",
                "\r\n",
                "This is an automatically generated Delivery Status Notification.\r\n",
                "\r\n",
                "Delivery to the following recipients failed:\r\n",
                "\r\n",
                "{recipient_list}\r\n",
                "\r\n",
                "Error: {error}\r\n",
                "\r\n",
                "--{boundary}\r\n",
                "Content-Type: message/delivery-status\r\n",
                "\r\n",
                "Reporting-MTA: dns; localhost\r\n",
                "Arrival-Date: {date}\r\n",
                "\r\n",
                "{recipients_report}\r\n",
                "--{boundary}\r\n",
                "Content-Type: text/rfc822-headers\r\n",
                "\r\n",
                "{original_headers}\r\n",
                "--{boundary}--\r\n",
            ),
            sender = self.bounce_sender,
            original_sender = original_envelope.mail_from,
            date = date,
            message_id = message_id,
            boundary = boundary,
            recipient_list = original_envelope.rcpt_to.join(", "),
            error = error_message,
            recipients_report = recipients_report,
            original_headers = original_headers,
        );

        let envelope = Envelope {
            mail_from: self.bounce_sender.clone(),
            rcpt_to: vec![original_envelope.mail_from.clone()],
        };

        Some((envelope, body.into_bytes()))
    }
}

impl Default for BounceGenerator {
    fn default() -> Self {
        Self::new(None, true)
    }
}

/// Extract headers from a raw message (everything before the first blank line).
fn extract_headers(message: &[u8]) -> String {
    let msg = String::from_utf8_lossy(message);
    if let Some(pos) = msg.find("\r\n\r\n") {
        msg[..pos].to_string()
    } else if let Some(pos) = msg.find("\n\n") {
        msg[..pos].to_string()
    } else {
        msg.to_string()
    }
}
