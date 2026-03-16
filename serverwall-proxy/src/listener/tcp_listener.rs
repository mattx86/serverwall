use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

/// Accepts plain TCP connections on one or more bound addresses.
///
/// Tracks active connection count and enforces an optional maximum.
/// Calls a user-supplied handler for each accepted connection.
pub struct TcpListenerTask {
    bind_addrs: Vec<String>,
    frontend_name: String,
    max_connections: Option<usize>,
    active_connections: Arc<AtomicUsize>,
}

impl TcpListenerTask {
    /// Create a new TCP listener task.
    ///
    /// * `bind_addrs` - One or more addresses to listen on (e.g. `"0.0.0.0:8080"`).
    /// * `frontend_name` - Name of the frontend, used for logging.
    /// * `max_connections` - Optional cap on concurrent connections.
    pub fn new(
        bind_addrs: Vec<String>,
        frontend_name: String,
        max_connections: Option<usize>,
    ) -> Self {
        Self {
            bind_addrs,
            frontend_name,
            max_connections,
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Bind to all configured addresses and accept connections in a loop.
    ///
    /// For each accepted connection the `handler` closure is invoked with:
    ///   - the accepted `TcpStream`
    ///   - the peer `SocketAddr`
    ///   - the local `SocketAddr` the connection arrived on
    ///
    /// The handler should return a future that processes the connection.
    /// Each connection is spawned as its own tokio task.
    ///
    /// The loop terminates when `shutdown_rx` receives `true`.
    pub async fn run<H, Fut>(
        &self,
        handler: H,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()>
    where
        H: Fn(TcpStream, SocketAddr, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(handler);

        // Bind all listeners
        let mut listeners = Vec::new();
        for addr in &self.bind_addrs {
            let listener = TcpListener::bind(addr).await?;
            let local_addr = listener.local_addr()?;
            tracing::info!(
                frontend = %self.frontend_name,
                address = %local_addr,
                "TCP listener bound",
            );
            listeners.push(listener);
        }

        if listeners.is_empty() {
            anyhow::bail!(
                "frontend '{}': no listen addresses configured",
                self.frontend_name
            );
        }

        // For a single listener, use a simple accept loop.
        // For multiple listeners, we use select! across all.
        if listeners.len() == 1 {
            self.accept_loop_single(
                &listeners[0],
                handler,
                &mut shutdown_rx,
            )
            .await
        } else {
            self.accept_loop_multi(
                listeners,
                handler,
                &mut shutdown_rx,
            )
            .await
        }
    }

    /// Accept loop for a single listener (most common case).
    async fn accept_loop_single<H, Fut>(
        &self,
        listener: &TcpListener,
        handler: Arc<H>,
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()>
    where
        H: Fn(TcpStream, SocketAddr, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let local_addr = listener.local_addr()?;

        loop {
            tokio::select! {
                biased;

                result = shutdown_rx.changed() => {
                    if result.is_ok() && *shutdown_rx.borrow() {
                        tracing::info!(
                            frontend = %self.frontend_name,
                            "TCP listener shutting down",
                        );
                        return Ok(());
                    }
                }

                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            self.dispatch_connection(
                                stream, peer_addr, local_addr, handler.clone(),
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                frontend = %self.frontend_name,
                                error = %e,
                                "failed to accept TCP connection",
                            );
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    }

    /// Accept loop for multiple listeners using spawned tasks per listener.
    async fn accept_loop_multi<H, Fut>(
        &self,
        listeners: Vec<TcpListener>,
        handler: Arc<H>,
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()>
    where
        H: Fn(TcpStream, SocketAddr, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // Use a shared channel to funnel accepted connections from all listeners
        let (accept_tx, mut accept_rx) =
            tokio::sync::mpsc::channel::<(TcpStream, SocketAddr, SocketAddr)>(64);

        let _active = self.active_connections.clone();
        let _max_connections = self.max_connections;
        let frontend_name = self.frontend_name.clone();

        // Spawn an accept task for each listener
        let mut accept_tasks = Vec::new();
        for listener in listeners {
            let tx = accept_tx.clone();
            let name = frontend_name.clone();
            let mut rx = shutdown_rx.clone();

            accept_tasks.push(tokio::spawn(async move {
                let local_addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!(frontend = %name, error = %e, "cannot get local addr");
                        return;
                    }
                };

                loop {
                    tokio::select! {
                        biased;

                        result = rx.changed() => {
                            if result.is_ok() && *rx.borrow() {
                                return;
                            }
                        }

                        result = listener.accept() => {
                            match result {
                                Ok((stream, peer_addr)) => {
                                    if tx.send((stream, peer_addr, local_addr)).await.is_err() {
                                        return;
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        frontend = %name,
                                        error = %e,
                                        "failed to accept TCP connection",
                                    );
                                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                                }
                            }
                        }
                    }
                }
            }));
        }

        // Drop our copy of the sender so the channel closes when all accept tasks end
        drop(accept_tx);

        // Dispatch loop
        loop {
            tokio::select! {
                biased;

                result = shutdown_rx.changed() => {
                    if result.is_ok() && *shutdown_rx.borrow() {
                        tracing::info!(
                            frontend = %self.frontend_name,
                            "TCP listener shutting down",
                        );
                        break;
                    }
                }

                accepted = accept_rx.recv() => {
                    match accepted {
                        Some((stream, peer_addr, local_addr)) => {
                            self.dispatch_connection(
                                stream, peer_addr, local_addr, handler.clone(),
                            );
                        }
                        None => {
                            // All accept tasks have exited
                            break;
                        }
                    }
                }
            }
        }

        // Wait for accept tasks to finish
        for task in accept_tasks {
            let _ = task.await;
        }

        Ok(())
    }

    /// Check connection limits and spawn a handler task for an accepted connection.
    fn dispatch_connection<H, Fut>(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        handler: Arc<H>,
    ) where
        H: Fn(TcpStream, SocketAddr, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // Enforce max connections
        if let Some(max) = self.max_connections {
            let current = self.active_connections.load(Ordering::Relaxed);
            if current >= max {
                tracing::warn!(
                    frontend = %self.frontend_name,
                    current,
                    max,
                    peer = %peer_addr,
                    "max connections reached, rejecting",
                );
                drop(stream);
                return;
            }
        }

        let active = self.active_connections.clone();
        active.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            handler(stream, peer_addr, local_addr).await;
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}
