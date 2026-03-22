use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use serverwall_core::config::schema::SmtpHeadersConfig;
use serverwall_core::logging::PostfixLogEntry;
use serverwall_core::proto::smtp::{self, SmtpCommand};

use serverwall_antispam::headers::SpamHeaderBuilder;
use serverwall_antispam::lists::{AllowList, BlockList};
use serverwall_antispam::pipeline::{
    AntispamPipeline, EnvelopeContext, MessageContext, PipelineDecision,
};
use serverwall_antispam::result::AuthenticationResults;
use serverwall_antispam::score::{SpamScore, SpamVerdict};

/// Tracks the current phase of an SMTP conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpState {
    Connected,
    BannerSent,
    HeloReceived,
    MailFrom,
    RcptTo,
    Data,
    Proxying,
    Quit,
}

/// SMTP proxy result for logging.
pub struct SmtpProxyResult {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub verdict: String,
    pub spam_score: f64,
    pub bytes_from_client: u64,
    pub bytes_from_backend: u64,
    pub duration_secs: f64,
}

/// SMTP-aware proxy that understands the SMTP state machine
/// and can apply policy at each stage.
pub struct SmtpProxy {
    pub backend_addr: SocketAddr,
    /// Opaque backend tag included in Received headers (does not expose backend address).
    pub backend_tag: String,
    pub state: SmtpState,
    pipeline: Arc<AntispamPipeline>,
    allow_list: Arc<AllowList>,
    block_list: Arc<BlockList>,
    hostname: String,
    /// JA3 TLS fingerprint for this connection (None for plaintext SMTP).
    ja3_fingerprint: Option<String>,
    /// Controls which headers are injected into forwarded messages.
    smtp_headers: SmtpHeadersConfig,
}

impl SmtpProxy {
    pub fn new(
        backend_addr: SocketAddr,
        backend_tag: String,
        pipeline: Arc<AntispamPipeline>,
        allow_list: Arc<AllowList>,
        block_list: Arc<BlockList>,
        hostname: String,
        ja3_fingerprint: Option<String>,
        smtp_headers: SmtpHeadersConfig,
    ) -> Self {
        Self {
            backend_addr,
            backend_tag,
            state: SmtpState::Connected,
            pipeline,
            allow_list,
            block_list,
            hostname,
            ja3_fingerprint,
            smtp_headers,
        }
    }

    /// Run the full SMTP proxy session.
    ///
    /// `client` is the already-accepted (and possibly TLS-terminated) stream
    /// from the connecting MTA/MUA.
    pub async fn proxy<C>(
        &mut self,
        client: C,
        peer_addr: SocketAddr,
    ) -> std::io::Result<SmtpProxyResult>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let start = Instant::now();
        let connect_time = Instant::now();

        let mut client_reader = BufReader::new(client);
        let mut bytes_from_client: u64 = 0;
        let mut bytes_from_backend: u64 = 0;

        let mut mail_from = String::new();
        let mut rcpt_to: Vec<String> = Vec::new();
        let mut helo_domain = String::new();
        let mut early_talker = false;
        let pipelining_detected = false;
        let mut command_count: u32 = 0;

        // ---- Phase 1: Send banner ----
        let banner = format!("220 {} ESMTP\r\n", self.hostname);
        let banner_sent_time = Instant::now();

        // Check for early talker: see if client has sent data before we sent banner.
        // We use a non-blocking peek.
        {
            let buf = client_reader.fill_buf().await?;
            if !buf.is_empty() {
                early_talker = true;
                tracing::debug!(client = %peer_addr, "early talker detected");
            }
        }

        let writer = client_reader.get_mut();
        writer.write_all(banner.as_bytes()).await?;
        writer.flush().await?;
        bytes_from_backend += banner.len() as u64;
        self.state = SmtpState::BannerSent;

        // ---- Phase 2: SMTP command loop ----
        let mut data_buffer: Vec<u8> = Vec::new();
        let mut allowed = false;

        loop {
            let mut line = String::new();
            let n = client_reader.read_line(&mut line).await?;
            if n == 0 {
                // Client disconnected.
                break;
            }
            bytes_from_client += n as u64;
            command_count += 1;

            let cmd = smtp::parse_command(&line);

            match cmd {
                SmtpCommand::Ehlo(domain) | SmtpCommand::Helo(domain) => {
                    helo_domain = domain;
                    self.state = SmtpState::HeloReceived;

                    // Respond with capabilities.
                    let response = format!(
                        "250-{}\r\n250-PIPELINING\r\n250-SIZE 26214400\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
                        self.hostname,
                    );
                    let writer = client_reader.get_mut();
                    writer.write_all(response.as_bytes()).await?;
                    writer.flush().await?;
                    bytes_from_backend += response.len() as u64;
                }

                SmtpCommand::StartTls => {
                    // We handle TLS at the listener layer.  If client asks for
                    // STARTTLS here, the connection is already plaintext and we
                    // would need to upgrade.  For SMTPS frontends TLS is already
                    // terminated.  For STARTTLS frontends the listener handles
                    // the upgrade before we get here.  So reply 454 if we reach this.
                    let resp = "454 4.7.0 TLS not available\r\n";
                    let writer = client_reader.get_mut();
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                    bytes_from_backend += resp.len() as u64;
                }

                SmtpCommand::MailFrom(sender) => {
                    mail_from = sender.trim_matches(|c| c == '<' || c == '>').to_string();

                    // Block list check.
                    if self.block_list.matches(peer_addr.ip(), &mail_from) {
                        let resp = "550 5.7.1 Sender blocked\r\n";
                        let writer = client_reader.get_mut();
                        writer.write_all(resp.as_bytes()).await?;
                        writer.flush().await?;
                        bytes_from_backend += resp.len() as u64;
                        self.state = SmtpState::Quit;
                        break;
                    }

                    self.state = SmtpState::MailFrom;
                    let resp = "250 2.1.0 Ok\r\n";
                    let writer = client_reader.get_mut();
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                    bytes_from_backend += resp.len() as u64;
                }

                SmtpCommand::RcptTo(recipient) => {
                    let addr = recipient.trim_matches(|c| c == '<' || c == '>').to_string();

                    // Recipient block list check.
                    if self.block_list.contains_recipient(&addr) {
                        let resp = "550 5.7.1 Recipient blocked\r\n";
                        let writer = client_reader.get_mut();
                        writer.write_all(resp.as_bytes()).await?;
                        writer.flush().await?;
                        bytes_from_backend += resp.len() as u64;
                        continue;
                    }

                    rcpt_to.push(addr);

                    // Allow list bypass check.
                    if self.allow_list.matches(peer_addr.ip(), &mail_from) {
                        allowed = true;
                    }

                    self.state = SmtpState::RcptTo;
                    let resp = "250 2.1.5 Ok\r\n";
                    let writer = client_reader.get_mut();
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                    bytes_from_backend += resp.len() as u64;
                }

                SmtpCommand::Data => {
                    if self.state != SmtpState::RcptTo && self.state != SmtpState::MailFrom {
                        let resp = "503 5.5.1 Bad sequence of commands\r\n";
                        let writer = client_reader.get_mut();
                        writer.write_all(resp.as_bytes()).await?;
                        writer.flush().await?;
                        bytes_from_backend += resp.len() as u64;
                        continue;
                    }

                    self.state = SmtpState::Data;
                    let resp = "354 End data with <CR><LF>.<CR><LF>\r\n";
                    let writer = client_reader.get_mut();
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                    bytes_from_backend += resp.len() as u64;

                    // Read DATA until lone ".\r\n".
                    data_buffer.clear();
                    loop {
                        let mut data_line = String::new();
                        let dn = client_reader.read_line(&mut data_line).await?;
                        if dn == 0 {
                            break;
                        }
                        bytes_from_client += dn as u64;
                        if data_line == ".\r\n" || data_line == ".\n" {
                            break;
                        }
                        // Dot-stuffing removal.
                        if data_line.starts_with("..") {
                            data_buffer.extend_from_slice(data_line[1..].as_bytes());
                        } else {
                            data_buffer.extend_from_slice(data_line.as_bytes());
                        }
                    }

                    // ---- Antispam evaluation ----
                    let envelope = EnvelopeContext {
                        client_ip: peer_addr.ip(),
                        helo_domain: helo_domain.clone(),
                        mail_from: mail_from.clone(),
                        rcpt_to: rcpt_to.clone(),
                        early_talker,
                        connect_time,
                        banner_sent_time,
                        command_count,
                        pipelining_detected,
                        ja3_fingerprint: self.ja3_fingerprint.clone(),
                    };

                    // Run pre-DATA checks.
                    let (pre_decision, pre_score, pre_contribs) =
                        self.pipeline.run_pre_data(&envelope).await;

                    if let PipelineDecision::Reject(code, reason) = &pre_decision {
                        let resp = format!("{} 5.7.1 {}\r\n", code, reason);
                        let writer = client_reader.get_mut();
                        writer.write_all(resp.as_bytes()).await?;
                        writer.flush().await?;
                        bytes_from_backend += resp.len() as u64;
                        // Log and continue to next message (RSET-like).
                        log_smtp_session(
                            &self.hostname,
                            &mail_from,
                            &rcpt_to,
                            &self.backend_addr,
                            pre_score.0,
                            "rejected",
                            &reason,
                        );
                        // Reset for next transaction.
                        mail_from.clear();
                        rcpt_to.clear();
                        data_buffer.clear();
                        self.state = SmtpState::HeloReceived;
                        continue;
                    }

                    if let PipelineDecision::TempFail(reason) = &pre_decision {
                        let resp = format!("451 4.7.1 {}\r\n", reason);
                        let writer = client_reader.get_mut();
                        writer.write_all(resp.as_bytes()).await?;
                        writer.flush().await?;
                        bytes_from_backend += resp.len() as u64;
                        mail_from.clear();
                        rcpt_to.clear();
                        data_buffer.clear();
                        self.state = SmtpState::HeloReceived;
                        continue;
                    }

                    // If in allow list, skip post-DATA checks.
                    if allowed {
                        let report = serverwall_antispam::result::SpamReport {
                            score: SpamScore::new(),
                            verdict: SpamVerdict::Clean,
                            contributions: Vec::new(),
                            auth_results: AuthenticationResults::default(),
                        };

                        self.state = SmtpState::Proxying;
                        let backend_resp =
                            self.forward_to_backend(&data_buffer, &mail_from, &rcpt_to, &report, peer_addr.ip()).await;
                        match backend_resp {
                            Ok((resp_text, b2c)) => {
                                bytes_from_backend += b2c;
                                let writer = client_reader.get_mut();
                                writer.write_all(resp_text.as_bytes()).await?;
                                writer.flush().await?;
                                bytes_from_backend += resp_text.len() as u64;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "backend connection failed");
                                let resp = "451 4.3.0 Backend unavailable\r\n";
                                let writer = client_reader.get_mut();
                                writer.write_all(resp.as_bytes()).await?;
                                writer.flush().await?;
                                bytes_from_backend += resp.len() as u64;
                            }
                        }
                        mail_from.clear();
                        rcpt_to.clear();
                        data_buffer.clear();
                        self.state = SmtpState::HeloReceived;
                        continue;
                    }

                    // Run post-DATA checks.
                    let msg_ctx = MessageContext {
                        envelope: EnvelopeContext {
                            client_ip: peer_addr.ip(),
                            helo_domain: helo_domain.clone(),
                            mail_from: mail_from.clone(),
                            rcpt_to: rcpt_to.clone(),
                            early_talker,
                            connect_time,
                            banner_sent_time,
                            command_count,
                            pipelining_detected,
                            ja3_fingerprint: self.ja3_fingerprint.clone(),
                        },
                        raw_message: data_buffer.clone(),
                    };

                    let auth_results = AuthenticationResults::default();
                    let report_result = self
                        .pipeline
                        .run_post_data(&msg_ctx, pre_score, pre_contribs, auth_results)
                        .await;

                    match report_result {
                        Err(PipelineDecision::Reject(code, reason)) => {
                            let resp = format!("{} 5.7.1 {}\r\n", code, reason);
                            let writer = client_reader.get_mut();
                            writer.write_all(resp.as_bytes()).await?;
                            writer.flush().await?;
                            bytes_from_backend += resp.len() as u64;
                            log_smtp_session(
                                &self.hostname,
                                &mail_from,
                                &rcpt_to,
                                &self.backend_addr,
                                0.0,
                                "rejected",
                                &reason,
                            );
                        }
                        Err(PipelineDecision::TempFail(reason)) => {
                            let resp = format!("451 4.7.1 {}\r\n", reason);
                            let writer = client_reader.get_mut();
                            writer.write_all(resp.as_bytes()).await?;
                            writer.flush().await?;
                            bytes_from_backend += resp.len() as u64;
                        }
                        Ok(report) => {
                            match report.verdict {
                                SpamVerdict::Spam => {
                                    // SPAM: reject, do NOT forward.
                                    let resp = "550 5.7.1 Message rejected as spam\r\n";
                                    let writer = client_reader.get_mut();
                                    writer.write_all(resp.as_bytes()).await?;
                                    writer.flush().await?;
                                    bytes_from_backend += resp.len() as u64;
                                    log_smtp_session(
                                        &self.hostname,
                                        &mail_from,
                                        &rcpt_to,
                                        &self.backend_addr,
                                        report.score.0,
                                        "rejected",
                                        "spam",
                                    );
                                }
                                SpamVerdict::Suspect | SpamVerdict::Clean => {
                                    // Forward to backend with headers.
                                    self.state = SmtpState::Proxying;
                                    let backend_resp =
                                        self.forward_to_backend(&data_buffer, &mail_from, &rcpt_to, &report, peer_addr.ip()).await;
                                    match backend_resp {
                                        Ok((resp_text, b2c)) => {
                                            bytes_from_backend += b2c;
                                            let writer = client_reader.get_mut();
                                            writer.write_all(resp_text.as_bytes()).await?;
                                            writer.flush().await?;
                                            bytes_from_backend += resp_text.len() as u64;
                                            let status = match report.verdict {
                                                SpamVerdict::Suspect => "suspect",
                                                _ => "sent",
                                            };
                                            log_smtp_session(
                                                &self.hostname,
                                                &mail_from,
                                                &rcpt_to,
                                                &self.backend_addr,
                                                report.score.0,
                                                status,
                                                "delivered",
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!(error = %e, "backend connection failed");
                                            let resp = "451 4.3.0 Backend unavailable\r\n";
                                            let writer = client_reader.get_mut();
                                            writer.write_all(resp.as_bytes()).await?;
                                            writer.flush().await?;
                                            bytes_from_backend += resp.len() as u64;
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }

                    // Reset for next transaction.
                    mail_from.clear();
                    rcpt_to.clear();
                    data_buffer.clear();
                    allowed = false;
                    self.state = SmtpState::HeloReceived;
                }

                SmtpCommand::Rset => {
                    mail_from.clear();
                    rcpt_to.clear();
                    data_buffer.clear();
                    allowed = false;
                    if self.state != SmtpState::BannerSent && self.state != SmtpState::Connected {
                        self.state = SmtpState::HeloReceived;
                    }
                    let resp = "250 2.0.0 Ok\r\n";
                    let writer = client_reader.get_mut();
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                    bytes_from_backend += resp.len() as u64;
                }

                SmtpCommand::Noop => {
                    let resp = "250 2.0.0 Ok\r\n";
                    let writer = client_reader.get_mut();
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                    bytes_from_backend += resp.len() as u64;
                }

                SmtpCommand::Quit => {
                    let resp = "221 2.0.0 Bye\r\n";
                    let writer = client_reader.get_mut();
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                    bytes_from_backend += resp.len() as u64;
                    self.state = SmtpState::Quit;
                    break;
                }

                _ => {
                    let resp = "502 5.5.2 Command not recognized\r\n";
                    let writer = client_reader.get_mut();
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                    bytes_from_backend += resp.len() as u64;
                }
            }
        }

        Ok(SmtpProxyResult {
            mail_from,
            rcpt_to,
            verdict: format!("{:?}", self.state),
            spam_score: 0.0,
            bytes_from_client,
            bytes_from_backend,
            duration_secs: start.elapsed().as_secs_f64(),
        })
    }

    /// Forward the message to the backend SMTP server (lazy connection).
    ///
    /// Prepends appropriate headers based on the spam report verdict:
    /// - SUSPECT: X-Spam-* headers + Authentication-Results
    /// - CLEAN: Authentication-Results only
    async fn forward_to_backend(
        &self,
        message_data: &[u8],
        mail_from: &str,
        rcpt_to: &[String],
        report: &serverwall_antispam::result::SpamReport,
        client_ip: IpAddr,
    ) -> std::io::Result<(String, u64)> {
        let mut backend = TcpStream::connect(self.backend_addr).await?;
        let mut backend_reader = BufReader::new(&mut backend);
        let mut bytes_from_backend: u64 = 0;

        // Read banner.
        let mut banner = String::new();
        let n = backend_reader.read_line(&mut banner).await?;
        bytes_from_backend += n as u64;

        // Send EHLO.
        let ehlo = format!("EHLO {}\r\n", self.hostname);
        backend_reader.get_mut().write_all(ehlo.as_bytes()).await?;
        backend_reader.get_mut().flush().await?;

        // Read EHLO response (multi-line).
        loop {
            let mut resp = String::new();
            let n = backend_reader.read_line(&mut resp).await?;
            bytes_from_backend += n as u64;
            if n == 0 || (resp.len() >= 4 && resp.as_bytes()[3] == b' ') {
                break;
            }
        }

        // Send MAIL FROM.
        let mail_cmd = format!("MAIL FROM:<{}>\r\n", mail_from);
        backend_reader.get_mut().write_all(mail_cmd.as_bytes()).await?;
        backend_reader.get_mut().flush().await?;
        let mut resp = String::new();
        let n = backend_reader.read_line(&mut resp).await?;
        bytes_from_backend += n as u64;

        // Send RCPT TO.
        for rcpt in rcpt_to {
            let rcpt_cmd = format!("RCPT TO:<{}>\r\n", rcpt);
            backend_reader.get_mut().write_all(rcpt_cmd.as_bytes()).await?;
            backend_reader.get_mut().flush().await?;
            resp.clear();
            let n = backend_reader.read_line(&mut resp).await?;
            bytes_from_backend += n as u64;
        }

        // Send DATA.
        backend_reader.get_mut().write_all(b"DATA\r\n").await?;
        backend_reader.get_mut().flush().await?;
        resp.clear();
        let n = backend_reader.read_line(&mut resp).await?;
        bytes_from_backend += n as u64;

        // Build injected headers.
        let header_builder = SpamHeaderBuilder::new();
        let mut injected_headers = Vec::new();

        // Received header (gated on smtp_headers.add_received, default: true).
        if self.smtp_headers.add_received {
            let received = format!(
                "Received: from unknown by {} (id={}); {}",
                self.hostname,
                self.backend_tag,
                chrono::Utc::now().to_rfc2822(),
            );
            injected_headers.push(("Received".to_string(), received));
        }

        // X-Forwarded-For header (gated on smtp_headers.x_forwarded_for, default: false).
        if self.smtp_headers.x_forwarded_for {
            injected_headers.push(("X-Forwarded-For".to_string(), client_ip.to_string()));
        }

        match report.verdict {
            SpamVerdict::Suspect => {
                // Add all X-Spam-* headers and Authentication-Results.
                let spam_headers = header_builder.build_headers(report, &self.hostname);
                injected_headers.extend(spam_headers);
            }
            SpamVerdict::Clean => {
                // Authentication-Results only.
                let auth = &report.auth_results;
                let ar_value = format!(
                    "{}; spf={} ; dkim={} ; dmarc={} ; arc={}",
                    self.hostname, auth.spf, auth.dkim, auth.dmarc, auth.arc,
                );
                injected_headers.push(("Authentication-Results".to_string(), ar_value));
            }
            SpamVerdict::Spam => {
                // Should not reach here (spam is rejected), but just in case.
            }
        }

        // Write injected headers.
        for (name, value) in &injected_headers {
            let header_line = format!("{}: {}\r\n", name, value);
            backend_reader.get_mut().write_all(header_line.as_bytes()).await?;
        }

        // Write original message.
        backend_reader.get_mut().write_all(message_data).await?;

        // End DATA with dot.
        backend_reader.get_mut().write_all(b"\r\n.\r\n").await?;
        backend_reader.get_mut().flush().await?;

        // Read final response.
        resp.clear();
        let n = backend_reader.read_line(&mut resp).await?;
        bytes_from_backend += n as u64;

        // Send QUIT.
        backend_reader.get_mut().write_all(b"QUIT\r\n").await?;
        backend_reader.get_mut().flush().await?;
        let mut quit_resp = String::new();
        let _ = backend_reader.read_line(&mut quit_resp).await;

        Ok((resp, bytes_from_backend))
    }
}

fn log_smtp_session(
    hostname: &str,
    mail_from: &str,
    rcpt_to: &[String],
    backend: &SocketAddr,
    spam_score: f64,
    status: &str,
    detail: &str,
) {
    let recipient = rcpt_to.first().map(|s| s.as_str()).unwrap_or("<>");
    let entry = PostfixLogEntry {
        timestamp: chrono::Utc::now(),
        hostname: hostname.to_string(),
        service_name: "serverwall/smtp".to_string(),
        pid: std::process::id(),
        queue_id: uuid::Uuid::new_v4().to_string()[..9].to_string(),
        sender: mail_from.to_string(),
        recipient: recipient.to_string(),
        relay: backend.to_string(),
        spam_score,
        status: status.to_string(),
        detail: detail.to_string(),
    };
    tracing::info!("{}", entry.format());
}
