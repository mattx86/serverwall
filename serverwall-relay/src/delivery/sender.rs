use anyhow::{Context, Result};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::tls::OutboundTls;

/// Result of a delivery attempt.
#[derive(Debug)]
pub enum DeliveryResult {
    /// Message was accepted by the remote server.
    Success(String),
    /// Temporary failure (4xx) — retry later.
    TempFail(String),
    /// Permanent failure (5xx) — do not retry.
    PermFail(String),
}

/// SMTP client for sending messages to remote MX servers.
pub struct SmtpSender {
    hostname: String,
    tls: Option<OutboundTls>,
}

impl SmtpSender {
    /// Create a new sender with the local hostname used in EHLO.
    pub fn new(hostname: String, tls: Option<OutboundTls>) -> Self {
        Self { hostname, tls }
    }

    /// Send a message to a remote SMTP server.
    ///
    /// `addr`      — remote IP:port to connect to
    /// `mx_host`   — hostname for EHLO / TLS SNI
    /// `mail_from` — envelope sender
    /// `rcpt_to`   — envelope recipients
    /// `message`   — raw RFC 5322 message bytes
    pub async fn send(
        &self,
        addr: std::net::SocketAddr,
        mx_host: &str,
        mail_from: &str,
        rcpt_to: &[String],
        message: &[u8],
    ) -> DeliveryResult {
        match self.send_inner(addr, mx_host, mail_from, rcpt_to, message).await {
            Ok(response) => DeliveryResult::Success(response),
            Err(e) => {
                let msg = e.to_string();
                if msg.starts_with('5') && msg.len() > 2 {
                    DeliveryResult::PermFail(msg)
                } else {
                    DeliveryResult::TempFail(msg)
                }
            }
        }
    }

    async fn send_inner(
        &self,
        addr: std::net::SocketAddr,
        mx_host: &str,
        mail_from: &str,
        rcpt_to: &[String],
        message: &[u8],
    ) -> Result<String> {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("failed to connect to {addr}"))?;

        // Use owned split so we can reunite the halves for STARTTLS upgrade.
        let (read_half, write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut writer = write_half;

        // Read banner.
        let banner = read_response(&mut reader).await?;
        ensure_positive(&banner)?;

        // EHLO
        write_cmd(&mut writer, &format!("EHLO {}", self.hostname)).await?;
        let ehlo_resp = read_response(&mut reader).await?;
        ensure_positive(&ehlo_resp)?;

        // Attempt STARTTLS upgrade if offered and our TLS config is enabled.
        let supports_starttls = ehlo_resp.to_uppercase().contains("STARTTLS");
        if supports_starttls {
            if let Some(tls) = &self.tls {
                if tls.is_enabled() {
                    write_cmd(&mut writer, "STARTTLS").await?;
                    let tls_resp = read_response(&mut reader).await?;
                    if tls_resp.starts_with('2') {
                        // Reunite the owned halves back into a TcpStream for the TLS upgrade.
                        let owned_read = reader.into_inner();
                        match owned_read.reunite(writer) {
                            Ok(tcp_stream) => {
                                match tls.upgrade(tcp_stream, mx_host).await {
                                    Ok(tls_stream) => {
                                        tracing::debug!(mx = %mx_host, "STARTTLS upgrade succeeded");
                                        let (r, w) = tokio::io::split(tls_stream);
                                        let mut tls_reader = BufReader::new(r);
                                        let mut tls_writer = w;
                                        // RFC 3207 §4.2 requires a fresh EHLO after STARTTLS.
                                        write_cmd(&mut tls_writer, &format!("EHLO {}", self.hostname)).await?;
                                        let _ = read_response(&mut tls_reader).await?;
                                        return smtp_conversation(
                                            &mut tls_reader,
                                            &mut tls_writer,
                                            mail_from,
                                            rcpt_to,
                                            message,
                                        )
                                        .await;
                                    }
                                    Err(e) => {
                                        tracing::warn!(mx = %mx_host, error = %e, "STARTTLS handshake failed");
                                        anyhow::bail!("STARTTLS handshake failed: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(mx = %mx_host, error = %e, "failed to reunite TCP halves for STARTTLS");
                                anyhow::bail!("STARTTLS reunite failed: {}", e);
                            }
                        }
                    }
                }
            }
        }

        // Plain-text SMTP conversation.
        smtp_conversation(&mut reader, &mut writer, mail_from, rcpt_to, message).await
    }
}

/// Perform the SMTP conversation (MAIL FROM → RCPT TO → DATA → body → QUIT).
///
/// Generic over reader/writer so it works on both plain TCP and TLS streams.
async fn smtp_conversation<R, W>(
    reader: &mut R,
    writer: &mut W,
    mail_from: &str,
    rcpt_to: &[String],
    message: &[u8],
) -> Result<String>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // MAIL FROM
    write_cmd(writer, &format!("MAIL FROM:<{mail_from}>")).await?;
    let from_resp = read_response(reader).await?;
    ensure_positive(&from_resp)?;

    // RCPT TO
    for rcpt in rcpt_to {
        write_cmd(writer, &format!("RCPT TO:<{rcpt}>")).await?;
        let rcpt_resp = read_response(reader).await?;
        ensure_positive(&rcpt_resp)?;
    }

    // DATA
    write_cmd(writer, "DATA").await?;
    let data_resp = read_response(reader).await?;
    if !data_resp.starts_with('3') {
        anyhow::bail!("{data_resp}");
    }

    // Send message body with dot-stuffing.
    for line in message.split(|&b| b == b'\n') {
        let line = if line.ends_with(b"\r") {
            &line[..line.len() - 1]
        } else {
            line
        };
        if line.starts_with(b".") {
            writer.write_all(b".").await?;
        }
        writer.write_all(line).await?;
        writer.write_all(b"\r\n").await?;
    }

    // Terminating dot.
    writer.write_all(b".\r\n").await?;
    writer.flush().await?;

    let final_resp = read_response(reader).await?;
    ensure_positive(&final_resp)?;

    // QUIT (best-effort).
    let _ = write_cmd(writer, "QUIT").await;

    Ok(final_resp)
}

/// Read a full SMTP response (may be multi-line).
async fn read_response<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<String> {
    let mut full_response = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            anyhow::bail!("connection closed unexpectedly");
        }
        full_response.push_str(&line);
        // Multi-line responses have '-' at position 3, final line has ' '
        if line.len() >= 4 && line.as_bytes()[3] == b' ' {
            break;
        }
        // Single-line response (3-digit code + space or just short)
        if line.len() < 4 {
            break;
        }
    }
    Ok(full_response.trim().to_string())
}

/// Ensure response starts with 2xx.
fn ensure_positive(response: &str) -> Result<()> {
    if response.starts_with('2') {
        Ok(())
    } else {
        anyhow::bail!("{response}")
    }
}

/// Write an SMTP command line.
async fn write_cmd<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, cmd: &str) -> Result<()> {
    writer.write_all(cmd.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    writer.flush().await?;
    Ok(())
}
