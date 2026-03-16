use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::net::TcpStream;
use tokio::sync::watch;

use serverwall_core::acl::AccessControlEngine;
use serverwall_core::balancer::{IpHash, LeastConnections, LoadBalancer, RoundRobin};
use serverwall_core::config::schema::{
    BalanceMethod, ServerWallConfig, ProtocolType,
};
use serverwall_core::health::HealthChecker;
use serverwall_core::tls::{CertStore, build_tls_acceptor};
use serverwall_core::types::{Backend, BackendId};

use serverwall_antispam::lists::{Blocklist, Whitelist};
use serverwall_antispam::pipeline::AntispamPipeline;

use crate::listener::TcpListenerTask;
use crate::listener::TlsListenerTask;
use crate::pipeline::RequestPipeline;
use crate::proxy::HttpProxy;
use crate::proxy::ImapProxy;
use crate::proxy::SmtpProxy;
use crate::proxy::TcpProxy;

/// Orchestrates all listeners, proxies, and health checkers.
pub struct Server {
    config: ServerWallConfig,
}

impl Server {
    /// Create a new server from the loaded configuration.
    pub fn from_config(config: ServerWallConfig) -> Self {
        Self { config }
    }

    /// Provided for backwards compatibility with the original stub.
    pub fn new() -> Self {
        Self {
            config: ServerWallConfig::default(),
        }
    }

    /// Run the server: set up backends, health checkers, and listeners.
    ///
    /// Blocks until a shutdown signal is received.
    pub async fn run(&self) -> anyhow::Result<()> {
        // Write PID file so that serverwallctl/webui can send SIGHUP for reload
        let pid_file = self.config.global.pid_file
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from(serverwall_core::DEFAULT_PID_FILE));
        if let Some(parent) = pid_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&pid_file, std::process::id().to_string());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        // Build backend pools (name -> Vec<Arc<Backend>>)
        let pools = build_backend_pools(&self.config);

        // Start health checkers for each pool
        for pool_config in &self.config.backend_pool {
            if let Some(backends) = pools.get(&pool_config.name) {
                let checker = HealthChecker::new(backends.clone(), pool_config);
                let rx = shutdown_rx.clone();
                tasks.push(tokio::spawn(async move {
                    checker.run(rx).await;
                }));
            }
        }

        // Start a listener for each frontend
        for frontend in &self.config.frontend {
            let pool_backends = pools
                .get(&frontend.backend_pool)
                .cloned()
                .unwrap_or_default();

            let balancer = build_balancer(frontend.balancer);

            let acl = AccessControlEngine::from_config(&frontend.acl)
                .map_err(|e| anyhow::anyhow!("ACL config error in frontend '{}': {}", frontend.name, e))?;

            let pipeline = Arc::new(RequestPipeline::new(acl, balancer, pool_backends));

            match frontend.protocol {
                ProtocolType::Tcp => {
                    let listener = TcpListenerTask::new(
                        frontend.listen.clone(),
                        frontend.name.clone(),
                        frontend.max_connections,
                    );
                    let rx = shutdown_rx.clone();
                    let frontend_name = frontend.name.clone();
                    let pipeline = pipeline.clone();

                    tasks.push(tokio::spawn(async move {
                        if let Err(e) = run_tcp_frontend(listener, pipeline, &frontend_name, rx).await {
                            tracing::error!(
                                frontend = %frontend_name,
                                error = %e,
                                "TCP frontend failed",
                            );
                        }
                    }));
                }
                ProtocolType::Imaps => {
                    let cert_store = Arc::new(CertStore::new());
                    let certified_key = CertStore::load_from_frontend(frontend)
                        .map_err(|e| anyhow::anyhow!("TLS error in frontend '{}': {}", frontend.name, e))?;
                    cert_store.add_from_cert(certified_key.clone());
                    cert_store.set_default(certified_key);

                    let acceptor = build_tls_acceptor(cert_store)
                        .map_err(|e| anyhow::anyhow!("TLS acceptor error in frontend '{}': {}", frontend.name, e))?;

                    let listener = TlsListenerTask::new(
                        frontend.listen.clone(),
                        frontend.name.clone(),
                        frontend.max_connections,
                        acceptor,
                    );
                    let rx = shutdown_rx.clone();
                    let frontend_name = frontend.name.clone();
                    let pipeline = pipeline.clone();

                    tasks.push(tokio::spawn(async move {
                        if let Err(e) = run_imap_frontend(listener, pipeline, &frontend_name, rx).await {
                            tracing::error!(
                                frontend = %frontend_name,
                                error = %e,
                                "IMAP frontend failed",
                            );
                        }
                    }));
                }
                ProtocolType::Https => {
                    let cert_store = Arc::new(CertStore::new());
                    let certified_key = CertStore::load_from_frontend(frontend)
                        .map_err(|e| anyhow::anyhow!("TLS error in frontend '{}': {}", frontend.name, e))?;
                    cert_store.add_from_cert(certified_key.clone());
                    cert_store.set_default(certified_key);

                    let acceptor = build_tls_acceptor(cert_store)
                        .map_err(|e| anyhow::anyhow!("TLS acceptor error in frontend '{}': {}", frontend.name, e))?;

                    let tls_listener = TlsListenerTask::new(
                        frontend.listen.clone(),
                        frontend.name.clone(),
                        frontend.max_connections,
                        acceptor,
                    );

                    // Build WAF engine if enabled
                    let waf = if frontend.waf_enabled {
                        Some(std::sync::Arc::new(
                            serverwall_waf::WafEngine::new(serverwall_waf::WafMode::Blocking),
                        ))
                    } else {
                        None
                    };

                    let http_proxy = Arc::new(HttpProxy::new(
                        frontend.clone(),
                        self.config.security.headers.clone(),
                        waf,
                        pipeline.clone(),
                    ));

                    let rx = shutdown_rx.clone();
                    let frontend_name = frontend.name.clone();
                    let pipeline = pipeline.clone();

                    tasks.push(tokio::spawn(async move {
                        if let Err(e) = run_https_frontend(
                            tls_listener,
                            pipeline,
                            http_proxy,
                            &frontend_name,
                            rx,
                        )
                        .await
                        {
                            tracing::error!(
                                frontend = %frontend_name,
                                error = %e,
                                "HTTPS frontend failed",
                            );
                        }
                    }));
                }
                ProtocolType::Smtps => {
                    let cert_store = Arc::new(CertStore::new());
                    let certified_key = CertStore::load_from_frontend(frontend)
                        .map_err(|e| anyhow::anyhow!("TLS error in frontend '{}': {}", frontend.name, e))?;
                    cert_store.add_from_cert(certified_key.clone());
                    cert_store.set_default(certified_key);

                    let acceptor = build_tls_acceptor(cert_store)
                        .map_err(|e| anyhow::anyhow!("TLS acceptor error in frontend '{}': {}", frontend.name, e))?;

                    let listener = TlsListenerTask::new(
                        frontend.listen.clone(),
                        frontend.name.clone(),
                        frontend.max_connections,
                        acceptor,
                    );

                    let rx = shutdown_rx.clone();
                    let frontend_name = frontend.name.clone();
                    let pipeline = pipeline.clone();
                    let antispam_pipeline = build_antispam_pipeline(&self.config.antispam);
                    let whitelist = build_whitelist(&self.config.antispam);
                    let blocklist = build_blocklist(&self.config.antispam);
                    let hostname = self.config.global.daemon_name.clone();

                    tasks.push(tokio::spawn(async move {
                        if let Err(e) = run_smtps_frontend(
                            listener,
                            pipeline,
                            antispam_pipeline,
                            whitelist,
                            blocklist,
                            hostname,
                            &frontend_name,
                            rx,
                        ).await {
                            tracing::error!(
                                frontend = %frontend_name,
                                error = %e,
                                "SMTPS frontend failed",
                            );
                        }
                    }));
                }
                ProtocolType::SmtpStarttls => {
                    // For STARTTLS, we listen on plain TCP and the SmtpProxy
                    // handles the TLS upgrade internally.  However, since TLS
                    // upgrade requires a TlsAcceptor, we build one and pass it
                    // through.  For this implementation, the proxy itself does
                    // not do inline STARTTLS -- it advertises STARTTLS but
                    // returns 454 if the listener didn't already upgrade.
                    // In a production system the listener would intercept
                    // STARTTLS and upgrade in-place.
                    let listener = TcpListenerTask::new(
                        frontend.listen.clone(),
                        frontend.name.clone(),
                        frontend.max_connections,
                    );

                    let rx = shutdown_rx.clone();
                    let frontend_name = frontend.name.clone();
                    let pipeline = pipeline.clone();
                    let antispam_pipeline = build_antispam_pipeline(&self.config.antispam);
                    let whitelist = build_whitelist(&self.config.antispam);
                    let blocklist = build_blocklist(&self.config.antispam);
                    let hostname = self.config.global.daemon_name.clone();

                    tasks.push(tokio::spawn(async move {
                        if let Err(e) = run_smtp_starttls_frontend(
                            listener,
                            pipeline,
                            antispam_pipeline,
                            whitelist,
                            blocklist,
                            hostname,
                            &frontend_name,
                            rx,
                        ).await {
                            tracing::error!(
                                frontend = %frontend_name,
                                error = %e,
                                "SMTP-STARTTLS frontend failed",
                            );
                        }
                    }));
                }
            }
        }

        // Wait for shutdown signal
        wait_for_shutdown_signal().await;

        tracing::info!("shutdown signal received, stopping all listeners");
        let _ = shutdown_tx.send(true);

        // Wait for all tasks to finish
        for task in tasks {
            let _ = task.await;
        }

        tracing::info!("server stopped");
        Ok(())
    }
}

/// Run a plain TCP frontend: accept connections, check ACL, select backend,
/// and proxy bidirectionally.
async fn run_tcp_frontend(
    listener: TcpListenerTask,
    pipeline: Arc<RequestPipeline>,
    frontend_name: &str,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = frontend_name.to_string();

    listener
        .run(
            move |client_stream: TcpStream, peer_addr: SocketAddr, local_addr: SocketAddr| {
                let pipeline = pipeline.clone();
                let name = name.clone();

                async move {
                    handle_tcp_connection(client_stream, peer_addr, local_addr, &pipeline, &name)
                        .await;
                }
            },
            shutdown_rx,
        )
        .await
}

/// Handle a single TCP proxy connection.
async fn handle_tcp_connection(
    client_stream: TcpStream,
    peer_addr: SocketAddr,
    _local_addr: SocketAddr,
    pipeline: &RequestPipeline,
    frontend_name: &str,
) {
    // Check ACL
    if let Err(e) = pipeline.check_acl(peer_addr.ip()) {
        tracing::debug!(
            frontend = %frontend_name,
            client = %peer_addr,
            error = %e,
            "connection denied by ACL",
        );
        return;
    }

    // Select backend
    let (backend, _guard) = match pipeline.select_backend(peer_addr.ip()) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(
                frontend = %frontend_name,
                client = %peer_addr,
                error = %e,
                "no backend available",
            );
            return;
        }
    };

    // Connect to backend
    let backend_stream = if backend.tls {
        // TLS backend - we need to wrap the stream
        match RequestPipeline::connect_backend_tls(&backend).await {
            Ok(tls_stream) => {
                // Proxy with TLS backend
                let start = std::time::Instant::now();
                match TcpProxy::proxy(client_stream, tls_stream).await {
                    Ok((c2b, b2c)) => {
                        tracing::info!(
                            frontend = %frontend_name,
                            client = %peer_addr,
                            backend_tag = %backend.tag,
                            bytes_in = c2b,
                            bytes_out = b2c,
                            duration_secs = start.elapsed().as_secs_f64(),
                            "TCP proxy session completed",
                        );
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::ConnectionReset
                            && e.kind() != std::io::ErrorKind::BrokenPipe
                        {
                            tracing::debug!(
                                frontend = %frontend_name,
                                client = %peer_addr,
                                backend_tag = %backend.tag,
                                error = %e,
                                "TCP proxy I/O error",
                            );
                        }
                    }
                }
                return;
            }
            Err(e) => {
                tracing::warn!(
                    frontend = %frontend_name,
                    client = %peer_addr,
                    backend_tag = %backend.tag,
                    error = %e,
                    "failed to connect to TLS backend",
                );
                return;
            }
        }
    } else {
        match RequestPipeline::connect_backend(&backend).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!(
                    frontend = %frontend_name,
                    client = %peer_addr,
                    backend_tag = %backend.tag,
                    error = %e,
                    "failed to connect to backend",
                );
                return;
            }
        }
    };

    // Proxy bidirectionally
    let start = std::time::Instant::now();
    match TcpProxy::proxy(client_stream, backend_stream).await {
        Ok((c2b, b2c)) => {
            tracing::info!(
                frontend = %frontend_name,
                client = %peer_addr,
                backend_tag = %backend.tag,
                bytes_in = c2b,
                bytes_out = b2c,
                duration_secs = start.elapsed().as_secs_f64(),
                "TCP proxy session completed",
            );
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::ConnectionReset
                && e.kind() != std::io::ErrorKind::BrokenPipe
            {
                tracing::debug!(
                    frontend = %frontend_name,
                    client = %peer_addr,
                    backend_tag = %backend.tag,
                    error = %e,
                    "TCP proxy I/O error",
                );
            }
        }
    }
}

/// Run an IMAPS frontend: TLS termination, then IMAP proxy.
async fn run_imap_frontend(
    listener: TlsListenerTask,
    pipeline: Arc<RequestPipeline>,
    frontend_name: &str,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = frontend_name.to_string();

    listener
        .run(
            move |tls_stream, peer_addr, _local_addr, sni| {
                let pipeline = pipeline.clone();
                let name = name.clone();

                async move {
                    // Check ACL
                    if let Err(e) = pipeline.check_acl(peer_addr.ip()) {
                        tracing::debug!(
                            frontend = %name,
                            client = %peer_addr,
                            sni = sni.as_deref().unwrap_or("-"),
                            error = %e,
                            "IMAP connection denied by ACL",
                        );
                        return;
                    }

                    // Select backend
                    let (backend, _guard) = match pipeline.select_backend(peer_addr.ip()) {
                        Ok(result) => result,
                        Err(e) => {
                            tracing::warn!(
                                frontend = %name,
                                client = %peer_addr,
                                error = %e,
                                "no IMAP backend available",
                            );
                            return;
                        }
                    };

                    // Connect to backend (plain TCP to IMAP backend)
                    let backend_stream = match RequestPipeline::connect_backend(&backend).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            tracing::warn!(
                                frontend = %name,
                                client = %peer_addr,
                                backend_tag = %backend.tag,
                                error = %e,
                                "failed to connect to IMAP backend",
                            );
                            return;
                        }
                    };

                    // Run IMAP proxy
                    match ImapProxy::proxy(
                        tls_stream,
                        backend_stream,
                        peer_addr,
                        backend.address,
                    )
                    .await
                    {
                        Ok(result) => {
                            tracing::info!(
                                frontend = %name,
                                client = %peer_addr,
                                backend_tag = %backend.tag,
                                username = result.username.as_deref().unwrap_or("-"),
                                bytes_in = result.bytes_from_client,
                                bytes_out = result.bytes_from_backend,
                                duration_secs = result.duration_secs,
                                "IMAP session completed",
                            );
                        }
                        Err(e) => {
                            tracing::debug!(
                                frontend = %name,
                                client = %peer_addr,
                                backend_tag = %backend.tag,
                                error = %e,
                                "IMAP proxy error",
                            );
                        }
                    }
                }
            },
            shutdown_rx,
        )
        .await
}

/// Run an HTTPS frontend: TLS termination, WAF inspection, then HTTP proxy.
async fn run_https_frontend(
    listener: TlsListenerTask,
    pipeline: Arc<RequestPipeline>,
    http_proxy: Arc<HttpProxy>,
    frontend_name: &str,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = frontend_name.to_string();

    listener
        .run(
            move |tls_stream, peer_addr, _local_addr, _sni| {
                let pipeline = pipeline.clone();
                let name = name.clone();
                let http_proxy = http_proxy.clone();

                async move {
                    // Check ACL
                    if let Err(e) = pipeline.check_acl(peer_addr.ip()) {
                        tracing::debug!(
                            frontend = %name,
                            client = %peer_addr,
                            error = %e,
                            "HTTPS connection denied by ACL",
                        );
                        return;
                    }

                    // Backend is selected per-request inside handle_connection
                    // (supports sticky-session routing based on request cookies).
                    if let Err(e) = http_proxy
                        .handle_connection(tls_stream, peer_addr.ip())
                        .await
                    {
                        tracing::debug!(
                            frontend = %name,
                            client = %peer_addr,
                            error = %e,
                            "HTTPS proxy error",
                        );
                    }
                }
            },
            shutdown_rx,
        )
        .await
}

/// Build the backend pools from config.
fn build_backend_pools(
    config: &ServerWallConfig,
) -> std::collections::HashMap<String, Vec<Arc<Backend>>> {
    let mut pools = std::collections::HashMap::new();

    for pool_config in &config.backend_pool {
        let mut backends = Vec::new();

        for bc in &pool_config.backend {
            let address: SocketAddr = match bc.address.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::error!(
                        pool = %pool_config.name,
                        backend = %bc.name,
                        address = %bc.address,
                        error = %e,
                        "invalid backend address, skipping",
                    );
                    continue;
                }
            };

            let mut backend = Backend::new(
                BackendId(bc.name.clone()),
                address,
                bc.weight,
                bc.tls,
            );
            backend.tls_verify = bc.tls_verify.unwrap_or(false);
            backend.tls_sni = bc.tls_sni.clone();
            backend.max_connections = bc.max_connections;
            backend.enabled.store(bc.enabled, Ordering::Relaxed);

            backends.push(Arc::new(backend));
        }

        pools.insert(pool_config.name.clone(), backends);
    }

    pools
}

/// Build a load balancer from the configured method.
fn build_balancer(method: BalanceMethod) -> Box<dyn LoadBalancer> {
    match method {
        BalanceMethod::RoundRobin => Box::new(RoundRobin::new()),
        BalanceMethod::LeastConnections => Box::new(LeastConnections::new()),
        BalanceMethod::IpHash => Box::new(IpHash::new()),
        // Sticky sessions use round-robin for initial placement; the cookie
        // carries the backend tag so repeat requests route to the same server.
        BalanceMethod::StickySession => Box::new(RoundRobin::new()),
    }
}

/// Build antispam pipeline from config.
fn build_antispam_pipeline(config: &serverwall_core::config::schema::AntispamConfig) -> Arc<AntispamPipeline> {
    Arc::new(AntispamPipeline::empty())
}

/// Build whitelist from config.
fn build_whitelist(config: &serverwall_core::config::schema::AntispamConfig) -> Arc<Whitelist> {
    Arc::new(Whitelist::from_config(
        config.whitelist.ips.clone(),
        config.whitelist.senders.clone(),
        config.whitelist.sender_domains.clone(),
    ))
}

/// Build blocklist from config.
fn build_blocklist(config: &serverwall_core::config::schema::AntispamConfig) -> Arc<Blocklist> {
    Arc::new(Blocklist::from_config(
        config.blocklist.ips.clone(),
        config.blocklist.senders.clone(),
        config.blocklist.sender_domains.clone(),
    ))
}

/// Run an SMTPS frontend: immediate TLS termination, then SMTP proxy.
async fn run_smtps_frontend(
    listener: TlsListenerTask,
    pipeline: Arc<RequestPipeline>,
    antispam_pipeline: Arc<AntispamPipeline>,
    whitelist: Arc<Whitelist>,
    blocklist: Arc<Blocklist>,
    hostname: String,
    frontend_name: &str,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = frontend_name.to_string();

    listener
        .run(
            move |tls_stream, peer_addr, _local_addr, _sni| {
                let pipeline = pipeline.clone();
                let name = name.clone();
                let antispam = antispam_pipeline.clone();
                let wl = whitelist.clone();
                let bl = blocklist.clone();
                let host = hostname.clone();

                async move {
                    // Check ACL
                    if let Err(e) = pipeline.check_acl(peer_addr.ip()) {
                        tracing::debug!(
                            frontend = %name,
                            client = %peer_addr,
                            error = %e,
                            "SMTP connection denied by ACL",
                        );
                        return;
                    }

                    // Select backend
                    let (backend, _guard) = match pipeline.select_backend(peer_addr.ip()) {
                        Ok(result) => result,
                        Err(e) => {
                            tracing::warn!(
                                frontend = %name,
                                client = %peer_addr,
                                error = %e,
                                "no SMTP backend available",
                            );
                            return;
                        }
                    };

                    let mut proxy = SmtpProxy::new(
                        backend.address,
                        backend.tag.clone(),
                        antispam,
                        wl,
                        bl,
                        host,
                    );

                    match proxy.proxy(tls_stream, peer_addr).await {
                        Ok(result) => {
                            tracing::info!(
                                frontend = %name,
                                client = %peer_addr,
                                backend_tag = %backend.tag,
                                mail_from = %result.mail_from,
                                verdict = %result.verdict,
                                spam_score = result.spam_score,
                                bytes_in = result.bytes_from_client,
                                bytes_out = result.bytes_from_backend,
                                duration_secs = result.duration_secs,
                                "SMTPS session completed",
                            );
                        }
                        Err(e) => {
                            if e.kind() != std::io::ErrorKind::ConnectionReset
                                && e.kind() != std::io::ErrorKind::BrokenPipe
                            {
                                tracing::debug!(
                                    frontend = %name,
                                    client = %peer_addr,
                                    error = %e,
                                    "SMTPS proxy I/O error",
                                );
                            }
                        }
                    }
                }
            },
            shutdown_rx,
        )
        .await
}

/// Run a SMTP-STARTTLS frontend: plain TCP accept, SMTP proxy handles
/// conversation (STARTTLS upgrade deferred to listener upgrade or rejected).
async fn run_smtp_starttls_frontend(
    listener: TcpListenerTask,
    pipeline: Arc<RequestPipeline>,
    antispam_pipeline: Arc<AntispamPipeline>,
    whitelist: Arc<Whitelist>,
    blocklist: Arc<Blocklist>,
    hostname: String,
    frontend_name: &str,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = frontend_name.to_string();

    listener
        .run(
            move |tcp_stream: TcpStream, peer_addr: SocketAddr, _local_addr: SocketAddr| {
                let pipeline = pipeline.clone();
                let name = name.clone();
                let antispam = antispam_pipeline.clone();
                let wl = whitelist.clone();
                let bl = blocklist.clone();
                let host = hostname.clone();

                async move {
                    // Check ACL
                    if let Err(e) = pipeline.check_acl(peer_addr.ip()) {
                        tracing::debug!(
                            frontend = %name,
                            client = %peer_addr,
                            error = %e,
                            "SMTP connection denied by ACL",
                        );
                        return;
                    }

                    // Select backend
                    let (backend, _guard) = match pipeline.select_backend(peer_addr.ip()) {
                        Ok(result) => result,
                        Err(e) => {
                            tracing::warn!(
                                frontend = %name,
                                client = %peer_addr,
                                error = %e,
                                "no SMTP backend available",
                            );
                            return;
                        }
                    };

                    let mut proxy = SmtpProxy::new(
                        backend.address,
                        backend.tag.clone(),
                        antispam,
                        wl,
                        bl,
                        host,
                    );

                    match proxy.proxy(tcp_stream, peer_addr).await {
                        Ok(result) => {
                            tracing::info!(
                                frontend = %name,
                                client = %peer_addr,
                                backend_tag = %backend.tag,
                                mail_from = %result.mail_from,
                                verdict = %result.verdict,
                                spam_score = result.spam_score,
                                bytes_in = result.bytes_from_client,
                                bytes_out = result.bytes_from_backend,
                                duration_secs = result.duration_secs,
                                "SMTP session completed",
                            );
                        }
                        Err(e) => {
                            if e.kind() != std::io::ErrorKind::ConnectionReset
                                && e.kind() != std::io::ErrorKind::BrokenPipe
                            {
                                tracing::debug!(
                                    frontend = %name,
                                    client = %peer_addr,
                                    error = %e,
                                    "SMTP proxy I/O error",
                                );
                            }
                        }
                    }
                }
            },
            shutdown_rx,
        )
        .await
}

/// Wait for a shutdown signal (Ctrl+C / SIGTERM).
async fn wait_for_shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("received Ctrl+C");
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
        tracing::info!("received Ctrl+C");
    }
}
