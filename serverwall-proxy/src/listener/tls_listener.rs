use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use serverwall_core::tls::ja3;

use super::tcp_listener::TcpListenerTask;

/// Accepts TLS connections on one or more bound addresses, performing the TLS
/// handshake before handing off to a handler.
///
/// Wraps a `TcpListenerTask` and adds TLS termination via `tokio_rustls`.
pub struct TlsListenerTask {
    tcp: TcpListenerTask,
    acceptor: TlsAcceptor,
}

impl TlsListenerTask {
    /// Create a new TLS listener task.
    ///
    /// * `bind_addrs` - One or more addresses to listen on.
    /// * `frontend_name` - Name of the frontend, used for logging.
    /// * `max_connections` - Optional cap on concurrent connections.
    /// * `acceptor` - A `TlsAcceptor` configured with the appropriate certificates.
    pub fn new(
        bind_addrs: Vec<String>,
        frontend_name: String,
        max_connections: Option<usize>,
        acceptor: TlsAcceptor,
    ) -> Self {
        Self {
            tcp: TcpListenerTask::new(bind_addrs, frontend_name, max_connections),
            acceptor,
        }
    }

    /// Return a clone of the active-connection counter for external monitoring / drain.
    pub fn active_connections(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        self.tcp.active_connections()
    }

    /// Bind, accept, perform TLS handshake, and dispatch to the handler.
    ///
    /// For each accepted connection the `handler` closure is invoked with:
    ///   - the `TlsStream<TcpStream>` after a successful handshake
    ///   - the peer `SocketAddr`
    ///   - the local `SocketAddr`
    ///   - the SNI hostname extracted from the handshake (if present)
    ///   - the JA3 fingerprint computed from the ClientHello (if parseable)
    ///
    /// JA3 is computed by peeking at the raw TCP bytes *before* the handshake
    /// so it captures what the client advertised, not what was negotiated.
    ///
    /// Connections that fail the TLS handshake are logged and dropped.
    pub async fn run<H, Fut>(
        &self,
        handler: H,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()>
    where
        H: Fn(TlsStream<TcpStream>, SocketAddr, SocketAddr, Option<String>, Option<String>) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let acceptor = self.acceptor.clone();
        let handler = Arc::new(handler);

        self.tcp
            .run(
                move |tcp_stream, peer_addr, local_addr| {
                    let acceptor = acceptor.clone();
                    let handler = handler.clone();

                    async move {
                        // Peek at the raw ClientHello bytes to compute JA3 *before*
                        // the handshake consumes them.  peek() does not advance the
                        // read position so rustls receives the full record intact.
                        let mut peek_buf = [0u8; 4096];
                        let ja3_hash = match tcp_stream.peek(&mut peek_buf).await {
                            Ok(n) if n > 0 => ja3::compute_from_bytes(&peek_buf[..n]),
                            _ => None,
                        };

                        // Perform TLS handshake
                        let tls_stream = match acceptor.accept(tcp_stream).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                tracing::debug!(
                                    peer = %peer_addr,
                                    error = %e,
                                    "TLS handshake failed",
                                );
                                return;
                            }
                        };

                        // Extract SNI hostname from the server connection
                        let sni = tls_stream
                            .get_ref()
                            .1
                            .server_name()
                            .map(|s| s.to_string());

                        handler(tls_stream, peer_addr, local_addr, sni, ja3_hash).await;
                    }
                },
                shutdown_rx,
            )
            .await
    }
}
