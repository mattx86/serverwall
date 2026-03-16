use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use serverwall_core::proto::smtp::{SmtpCommand, parse_command};

use crate::dkim::{DkimKeyStore, DkimSigner};
use crate::outbound_policy::OutboundPolicyChecker;
use crate::queue::message::Envelope;
use crate::queue::spool::FilesystemSpool;
use crate::trusted_hosts::TrustedHosts;

/// SMTP receiver for trusted internal hosts.
///
/// Listens on one or more ports, accepts connections only from trusted IPs
/// (no SMTP AUTH -- IP-based authorization), and enqueues messages into the
/// filesystem spool after policy checks and DKIM signing.
pub struct SmtpReceiver {
    listen_addrs: Vec<SocketAddr>,
    hostname: String,
    trusted_hosts: Arc<TrustedHosts>,
    spool: Arc<FilesystemSpool>,
    policy: Arc<OutboundPolicyChecker>,
    dkim_enabled: bool,
    dkim_signer: Arc<DkimSigner>,
    dkim_key_store: Arc<DkimKeyStore>,
}

impl SmtpReceiver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        listen_addrs: Vec<SocketAddr>,
        hostname: String,
        trusted_hosts: Arc<TrustedHosts>,
        spool: Arc<FilesystemSpool>,
        policy: Arc<OutboundPolicyChecker>,
        dkim_enabled: bool,
        dkim_signer: Arc<DkimSigner>,
        dkim_key_store: Arc<DkimKeyStore>,
    ) -> Self {
        Self {
            listen_addrs,
            hostname,
            trusted_hosts,
            spool,
            policy,
            dkim_enabled,
            dkim_signer,
            dkim_key_store,
        }
    }

    /// Start listening and accepting connections. Runs until shutdown signal.
    pub async fn run(self: Arc<Self>, shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        let mut handles = Vec::new();

        for addr in &self.listen_addrs {
            let listener = TcpListener::bind(addr).await?;
            tracing::info!(addr = %addr, "relay receiver listening");

            let this = self.clone();
            let mut rx = shutdown.clone();

            handles.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok((stream, peer_addr)) => {
                                    let session = SmtpSession {
                                        hostname: this.hostname.clone(),
                                        trusted_hosts: this.trusted_hosts.clone(),
                                        spool: this.spool.clone(),
                                        policy: this.policy.clone(),
                                        dkim_enabled: this.dkim_enabled,
                                        dkim_signer: this.dkim_signer.clone(),
                                        dkim_key_store: this.dkim_key_store.clone(),
                                        peer_addr,
                                    };
                                    tokio::spawn(async move {
                                        if let Err(e) = session.handle(stream).await {
                                            tracing::debug!(
                                                peer = %peer_addr,
                                                error = %e,
                                                "session error"
                                            );
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "accept error");
                                }
                            }
                        }
                        _ = rx.changed() => {
                            tracing::info!("listener shutting down");
                            return;
                        }
                    }
                }
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }
}

/// Per-connection SMTP session state.
struct SmtpSession {
    hostname: String,
    trusted_hosts: Arc<TrustedHosts>,
    spool: Arc<FilesystemSpool>,
    policy: Arc<OutboundPolicyChecker>,
    dkim_enabled: bool,
    dkim_signer: Arc<DkimSigner>,
    dkim_key_store: Arc<DkimKeyStore>,
    peer_addr: SocketAddr,
}

/// SMTP session state machine phases.
enum SessionState {
    Connected,
    Greeted,
    MailFrom(String),
    RcptTo(String, Vec<String>),
}

impl SmtpSession {
    async fn handle(self, stream: TcpStream) -> Result<()> {
        let peer_ip = self.peer_addr.ip();

        // IP-based authorization
        if !self.trusted_hosts.is_trusted(peer_ip) {
            let (_, mut writer) = tokio::io::split(stream);
            writer
                .write_all(b"554 5.7.1 Relay access denied\r\n")
                .await?;
            writer.flush().await?;
            tracing::warn!(peer = %self.peer_addr, "relay access denied (untrusted)");
            return Ok(());
        }

        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);

        // Send banner
        let banner = format!("220 {} ESMTP\r\n", self.hostname);
        writer.write_all(banner.as_bytes()).await?;

        let mut state = SessionState::Connected;

        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break; // Connection closed
            }

            let cmd = parse_command(&line);
            tracing::trace!(peer = %self.peer_addr, cmd = ?cmd, "received command");

            match cmd {
                SmtpCommand::Ehlo(domain) | SmtpCommand::Helo(domain) => {
                    let resp = format!(
                        "250-{}\r\n250-SIZE 26214400\r\n250-8BITMIME\r\n250-PIPELINING\r\n250 OK\r\n",
                        self.hostname
                    );
                    writer.write_all(resp.as_bytes()).await?;
                    state = SessionState::Greeted;
                    let _ = domain;
                }

                SmtpCommand::MailFrom(addr) => {
                    match state {
                        SessionState::Greeted
                        | SessionState::MailFrom(_)
                        | SessionState::RcptTo(_, _) => {}
                        _ => {
                            writer
                                .write_all(b"503 5.5.1 Bad sequence of commands\r\n")
                                .await?;
                            continue;
                        }
                    }

                    let sender = extract_address(&addr);

                    // Validate sender domain against allowed_sender_domains
                    if let Some(domain) = sender.rsplit('@').next() {
                        if let Err(reason) = self.policy.spf_alignment.check(domain) {
                            let resp = format!("550 5.7.1 {reason}\r\n");
                            writer.write_all(resp.as_bytes()).await?;
                            continue;
                        }
                    }

                    writer.write_all(b"250 2.1.0 OK\r\n").await?;
                    state = SessionState::MailFrom(sender);
                }

                SmtpCommand::RcptTo(addr) => {
                    let (mail_from, mut rcpts) = match state {
                        SessionState::MailFrom(ref mf) => (mf.clone(), Vec::new()),
                        SessionState::RcptTo(ref mf, ref r) => (mf.clone(), r.clone()),
                        _ => {
                            writer
                                .write_all(b"503 5.5.1 Bad sequence of commands\r\n")
                                .await?;
                            continue;
                        }
                    };

                    let recipient = extract_address(&addr);
                    rcpts.push(recipient);

                    // Check recipient limit
                    if let Err(reason) = self.policy.recipient_limit.check(rcpts.len()) {
                        let resp = format!("550 5.5.3 {reason}\r\n");
                        writer.write_all(resp.as_bytes()).await?;
                        continue;
                    }

                    writer.write_all(b"250 2.1.5 OK\r\n").await?;
                    state = SessionState::RcptTo(mail_from, rcpts);
                }

                SmtpCommand::Data => {
                    let (mail_from, rcpt_to) = match state {
                        SessionState::RcptTo(ref mf, ref r) if !r.is_empty() => {
                            (mf.clone(), r.clone())
                        }
                        _ => {
                            writer
                                .write_all(b"503 5.5.1 Bad sequence of commands\r\n")
                                .await?;
                            continue;
                        }
                    };

                    writer
                        .write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                        .await?;

                    // Read message data until lone dot
                    let mut message_data = Vec::new();
                    loop {
                        let mut data_line = String::new();
                        let dn = reader.read_line(&mut data_line).await?;
                        if dn == 0 {
                            return Ok(()); // premature close
                        }
                        let trimmed =
                            data_line.trim_end_matches("\r\n").trim_end_matches('\n');
                        if trimmed == "." {
                            break;
                        }
                        // Undo dot-stuffing
                        let line_bytes = if data_line.starts_with("..") {
                            &data_line[1..]
                        } else {
                            &data_line
                        };
                        message_data.extend_from_slice(line_bytes.as_bytes());
                    }

                    // Extract sender domain for policy checks
                    let sender_domain = mail_from
                        .rsplit('@')
                        .next()
                        .unwrap_or("unknown")
                        .to_string();

                    // Run outbound policy checks
                    if let Err(reason) =
                        self.policy.check(&sender_domain, rcpt_to.len(), &message_data)
                    {
                        let resp = format!("550 5.7.1 {reason}\r\n");
                        writer.write_all(resp.as_bytes()).await?;
                        state = SessionState::Greeted;
                        continue;
                    }

                    // DKIM sign
                    let final_message = if self.dkim_enabled {
                        if let Some(entry) = self.dkim_key_store.lookup(&sender_domain) {
                            match self.dkim_signer.sign(entry, &message_data) {
                                Ok(signed) => signed,
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "DKIM signing failed, sending unsigned"
                                    );
                                    message_data
                                }
                            }
                        } else {
                            message_data
                        }
                    } else {
                        message_data
                    };

                    // Enqueue to filesystem spool
                    let envelope = Envelope {
                        mail_from: mail_from.clone(),
                        rcpt_to: rcpt_to.clone(),
                    };

                    match self.spool.enqueue(envelope, final_message) {
                        Ok(queue_id) => {
                            let resp = format!("250 2.0.0 OK queued as {queue_id}\r\n");
                            writer.write_all(resp.as_bytes()).await?;
                            tracing::info!(
                                peer = %self.peer_addr,
                                queue_id = %queue_id,
                                from = %mail_from,
                                rcpt_count = rcpt_to.len(),
                                "message accepted"
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to enqueue message");
                            writer
                                .write_all(
                                    b"451 4.3.0 Internal error, try again later\r\n",
                                )
                                .await?;
                        }
                    }

                    state = SessionState::Greeted;
                }

                SmtpCommand::Rset => {
                    state = SessionState::Greeted;
                    writer.write_all(b"250 2.0.0 OK\r\n").await?;
                }

                SmtpCommand::Noop => {
                    writer.write_all(b"250 2.0.0 OK\r\n").await?;
                }

                SmtpCommand::Quit => {
                    writer.write_all(b"221 2.0.0 Bye\r\n").await?;
                    break;
                }

                SmtpCommand::Auth(_) => {
                    // No AUTH support -- trusted host model
                    writer
                        .write_all(b"502 5.5.1 AUTH not supported on relay\r\n")
                        .await?;
                }

                SmtpCommand::StartTls => {
                    writer
                        .write_all(b"502 5.5.1 STARTTLS not available\r\n")
                        .await?;
                }

                _ => {
                    writer
                        .write_all(b"500 5.5.2 Unrecognized command\r\n")
                        .await?;
                }
            }
        }

        Ok(())
    }
}

/// Extract a bare email address from an SMTP parameter like `<user@domain>` or `user@domain`.
fn extract_address(raw: &str) -> String {
    let s = raw.trim();
    if s.starts_with('<') && s.ends_with('>') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}
