use std::net::SocketAddr;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use serverwall_core::logging::ProtocolLogEntry;
use serverwall_core::proto::imap;

use super::tcp_proxy::TcpProxy;

/// IMAP-aware proxy that sniffs LOGIN credentials for logging purposes,
/// then delegates to bidirectional byte proxying.
///
/// For IMAPS (port 993) the TLS termination happens in the listener layer.
/// This proxy receives an already-decrypted stream.
pub struct ImapProxy;

/// Result of an IMAP proxy session, used for logging.
pub struct ImapProxyResult {
    /// Username extracted from IMAP LOGIN command, if seen.
    pub username: Option<String>,
    /// Bytes sent from the client to the backend.
    pub bytes_from_client: u64,
    /// Bytes sent from the backend to the client.
    pub bytes_from_backend: u64,
    /// Wall-clock duration of the session.
    pub duration_secs: f64,
}

impl ImapProxy {
    /// Run the IMAP proxy between a client stream and a backend TCP connection.
    ///
    /// The proxy works in two phases:
    ///
    /// 1. **Sniff phase**: Read lines from the client looking for a LOGIN
    ///    command. All data (including the backend greeting) is forwarded
    ///    transparently. Once LOGIN is seen (or a non-LOGIN command is sent),
    ///    the sniff phase ends.
    ///
    /// 2. **Proxy phase**: Hand off to `TcpProxy::proxy` for efficient
    ///    bidirectional byte copying.
    pub async fn proxy<C>(
        client: C,
        backend: TcpStream,
        client_addr: SocketAddr,
        backend_addr: SocketAddr,
    ) -> std::io::Result<ImapProxyResult>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let start = Instant::now();

        let mut client = BufReader::new(client);
        let mut backend = BufReader::new(backend);
        let mut username: Option<String> = None;
        let mut bytes_from_client: u64 = 0;
        let mut bytes_from_backend: u64 = 0;

        // Phase 1: Forward backend greeting to client
        {
            let mut greeting = String::new();
            let n = backend.read_line(&mut greeting).await?;
            if n == 0 {
                return Ok(ImapProxyResult {
                    username: None,
                    bytes_from_client: 0,
                    bytes_from_backend: 0,
                    duration_secs: start.elapsed().as_secs_f64(),
                });
            }
            bytes_from_backend += n as u64;

            // Forward greeting to client
            let writer = client.get_mut();
            writer.write_all(greeting.as_bytes()).await?;
            writer.flush().await?;
        }

        // Phase 2: Sniff client lines looking for LOGIN
        // We look at up to 10 lines from the client before giving up on sniffing.
        let sniff_limit = 10;
        for _ in 0..sniff_limit {
            let mut line = String::new();
            let n = client.read_line(&mut line).await?;
            if n == 0 {
                // Client disconnected
                return Ok(ImapProxyResult {
                    username,
                    bytes_from_client,
                    bytes_from_backend,
                    duration_secs: start.elapsed().as_secs_f64(),
                });
            }
            bytes_from_client += n as u64;

            // Forward client line to backend
            let backend_writer = backend.get_mut();
            backend_writer.write_all(line.as_bytes()).await?;
            backend_writer.flush().await?;

            // Try to parse IMAP command
            if let Some(cmd) = imap::parse_command(&line) {
                if cmd.command == "LOGIN" {
                    // Extract username from LOGIN args: LOGIN <username> <password>
                    username = extract_login_username(&cmd.args);
                    tracing::info!(
                        client = %client_addr,
                        backend = %backend_addr,
                        username = username.as_deref().unwrap_or("<unknown>"),
                        "IMAP LOGIN detected",
                    );
                }

                // Read the backend response to this command
                let mut resp = String::new();
                let n = backend.read_line(&mut resp).await?;
                if n > 0 {
                    bytes_from_backend += n as u64;
                    let writer = client.get_mut();
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                }

                // After seeing LOGIN or after the first authenticated command,
                // switch to opaque proxying.
                if cmd.command == "LOGIN" {
                    break;
                }

                // For CAPABILITY, NOOP, ID etc. continue sniffing
                if !matches!(
                    cmd.command.as_str(),
                    "CAPABILITY" | "NOOP" | "ID" | "STARTTLS" | "LOGOUT"
                ) {
                    // Unknown pre-auth command, stop sniffing
                    break;
                }

                if cmd.command == "LOGOUT" {
                    return Ok(ImapProxyResult {
                        username,
                        bytes_from_client,
                        bytes_from_backend,
                        duration_secs: start.elapsed().as_secs_f64(),
                    });
                }
            }
        }

        // Phase 3: Opaque bidirectional proxy for the rest of the session
        let client_inner = client.into_inner();
        let backend_inner = backend.into_inner();
        match TcpProxy::proxy(client_inner, backend_inner).await {
            Ok((c2b, b2c)) => {
                bytes_from_client += c2b;
                bytes_from_backend += b2c;
            }
            Err(e) => {
                // Connection reset / broken pipe is normal for IMAP sessions
                if e.kind() != std::io::ErrorKind::ConnectionReset
                    && e.kind() != std::io::ErrorKind::BrokenPipe
                {
                    tracing::debug!(
                        client = %client_addr,
                        backend = %backend_addr,
                        error = %e,
                        "IMAP proxy I/O error",
                    );
                }
            }
        }

        let duration_secs = start.elapsed().as_secs_f64();

        // Log the completed session
        let log_entry = ProtocolLogEntry {
            timestamp: chrono::Utc::now(),
            client: client_addr,
            backend: backend_addr,
            bytes_in: bytes_from_client,
            bytes_out: bytes_from_backend,
            duration_secs,
        };

        tracing::info!(
            protocol = "IMAP",
            username = username.as_deref().unwrap_or("-"),
            "{}", log_entry.format(),
        );

        Ok(ImapProxyResult {
            username,
            bytes_from_client,
            bytes_from_backend,
            duration_secs,
        })
    }
}

/// Extract the username from IMAP LOGIN arguments.
///
/// LOGIN args format: `<username> <password>`
/// The username may be quoted: `"user@example.com" "password"`
fn extract_login_username(args: &str) -> Option<String> {
    let args = args.trim();
    if args.starts_with('"') {
        // Quoted username
        if let Some(end) = args[1..].find('"') {
            return Some(args[1..=end].to_string());
        }
    }
    // Unquoted: first space-separated token
    args.split_whitespace().next().map(|s| s.to_string())
}
