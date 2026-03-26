use std::net::SocketAddr;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use serverwall_core::proto::stratum;

use super::TcpProxy;

/// Result of a completed Stratum proxy session.
pub struct StratumProxyResult {
    /// Worker name extracted from `mining.authorize`, if seen.
    pub worker: Option<String>,
    pub bytes_from_client: u64,
    pub bytes_from_backend: u64,
    pub duration_secs: f64,
}

/// Stratum V1 protocol-aware proxy.
///
/// **Phase 1 — Sniff**: reads up to 5 client messages, forwarding each to the
/// backend and returning the backend's response to the client. If a
/// `mining.authorize` message is seen, the worker name is extracted from
/// `params[0]` for logging. Sniffing stops after `mining.authorize` or after
/// 5 client messages, whichever comes first.
///
/// **Phase 2 — Opaque proxy**: the remainder of the session is handed off to
/// `TcpProxy::proxy()` for zero-copy bidirectional streaming.
pub struct StratumProxy;

impl StratumProxy {
    pub async fn proxy<C>(
        client: C,
        backend: TcpStream,
        _client_addr: SocketAddr,
    ) -> std::io::Result<StratumProxyResult>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let start = Instant::now();

        let mut client_buf  = BufReader::new(client);
        let mut backend_buf = BufReader::new(backend);

        let mut worker: Option<String> = None;
        let mut bytes_from_client: u64 = 0;
        let mut bytes_from_backend: u64 = 0;

        // Phase 1: sniff up to 5 client→backend messages.
        for _ in 0..5 {
            // Read one line from client.
            let mut client_line = String::new();
            let n = client_buf.read_line(&mut client_line).await?;
            if n == 0 {
                // Client disconnected during handshake.
                return Ok(StratumProxyResult {
                    worker,
                    bytes_from_client,
                    bytes_from_backend,
                    duration_secs: start.elapsed().as_secs_f64(),
                });
            }
            bytes_from_client += n as u64;

            // Check for mining.authorize to capture the worker name.
            let authorize = if let Some(msg) = stratum::parse_line(&client_line) {
                if msg.method.as_deref() == Some("mining.authorize") {
                    worker = stratum::extract_worker(&msg);
                    true
                } else {
                    false
                }
            } else {
                false
            };

            // Forward client line to backend.
            backend_buf.get_mut().write_all(client_line.as_bytes()).await?;
            backend_buf.get_mut().flush().await?;

            // Read one response from backend and forward to client.
            let mut backend_line = String::new();
            let m = backend_buf.read_line(&mut backend_line).await?;
            if m == 0 {
                return Ok(StratumProxyResult {
                    worker,
                    bytes_from_client,
                    bytes_from_backend,
                    duration_secs: start.elapsed().as_secs_f64(),
                });
            }
            bytes_from_backend += m as u64;
            client_buf.get_mut().write_all(backend_line.as_bytes()).await?;
            client_buf.get_mut().flush().await?;

            // Stop sniffing once we have the worker name.
            if authorize {
                break;
            }
        }

        // Phase 2: opaque bidirectional proxy for the rest of the session.
        let (c2b, b2c) =
            TcpProxy::proxy(client_buf.into_inner(), backend_buf.into_inner()).await?;

        Ok(StratumProxyResult {
            worker,
            bytes_from_client: bytes_from_client + c2b,
            bytes_from_backend: bytes_from_backend + b2c,
            duration_secs: start.elapsed().as_secs_f64(),
        })
    }
}
