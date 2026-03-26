mod state;
mod middleware;
mod static_files;
mod templates;
mod tls;
mod routes;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use clap::Parser;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use serverwall_core::acl::IpMatcher;
use serverwall_core::config::{editor, load_config, schema::{WafExclusions, WafMode, WafRulesetConfig}};
use serverwall_core::{DEFAULT_CONFIG_PATH, DEFAULT_WEBUI_PID_FILE};
use state::AppState;

/// ServerWall Web UI and management server.
#[derive(Parser, Debug)]
#[command(name = "serverwall-webui", version, about)]
pub struct Args {
    /// Path to the configuration file.
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    // Install the ring crypto provider for rustls before any TLS operations.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let args = Args::parse();

    // Load config (must precede tracing init so we know log_dir)
    let config = match load_config(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: failed to load config ({}), using defaults", e);
            serverwall_core::config::ServerWallConfig::default()
        }
    };

    // Initialize tracing — stdout (ANSI) + file (no ANSI)
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.global.log_level));
    let file_appender = tracing_appender::rolling::never(&config.global.log_dir, "serverwall-webui.log");
    let (non_blocking, _file_guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout).with_ansi(true).with_target(true))
        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking).with_ansi(false).with_target(true))
        .init();

    // Ensure "default" WAF ruleset exists (idempotent — add_waf_ruleset returns Err if already there)
    let _ = editor::add_waf_ruleset(&args.config, WafRulesetConfig {
        name: "default".to_string(),
        mode: WafMode::Blocking,
        anomaly_threshold: 5,
        paranoia_level: 1,
        rules_dir: None,
        exclusions: WafExclusions::default(),
        custom_rules: vec![],
    });

    if !config.webui.enabled {
        tracing::info!("webui disabled in config (webui.enabled = false), exiting");
        return;
    }

    let listen_addr = config.webui.listen.clone();
    let tls_cert = config.webui.tls_cert.clone();
    let tls_key = config.webui.tls_key.clone();
    let drain_secs = config.global.graceful_drain_secs;

    // Auto-generate a self-signed cert if the configured paths don't exist yet.
    // This ensures HTTPS works out of the box even before `serverwall --init` is run.
    if let (Some(cert_path), Some(key_path)) = (&tls_cert, &tls_key) {
        if !cert_path.exists() || !key_path.exists() {
            if let Some(parent) = cert_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let cn = std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "localhost".to_string());
            let extra_ips: Vec<std::net::IpAddr> = if_addrs::get_if_addrs()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|iface| {
                    let ip = iface.addr.ip();
                    if ip.is_loopback() { None } else { Some(ip) }
                })
                .collect();
            match serverwall_core::tls::generate_self_signed_cert(cert_path, key_path, &cn, &extra_ips) {
                Ok(()) => tracing::info!(
                    cert = %cert_path.display(),
                    "generated self-signed TLS certificate for web UI",
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    cert = %cert_path.display(),
                    "failed to generate self-signed TLS certificate",
                ),
            }
        }
    }

    // Graceful-shutdown channel: fired by SIGTERM or Ctrl-C.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    install_sigterm_handler(shutdown_tx);

    match (&tls_cert, &tls_key) {
        (Some(cert_path), Some(key_path)) => {
            match tls::load_tls_config(cert_path, key_path) {
                Ok(tls_config) => {
                    let tls_lock = Arc::new(RwLock::new(
                        TlsAcceptor::from(Arc::new(tls_config))
                    ));
                    let state = AppState::from_config(config, args.config.clone(), Some(tls_lock.clone()));
                    write_pid_file();
                    install_sighup_handler(state.clone());
                    let app = routes::build_router(state.clone());
                    serve_https(app, &listen_addr, tls_lock, state.ip_allow.clone(), shutdown_rx, drain_secs).await;
                }
                Err(e) => {
                    eprintln!(
                        "fatal: failed to load TLS certificate for webui: {}\n\
                         Refusing to start without TLS. Run `serverwall --init` to generate certs.",
                        e
                    );
                    std::process::exit(1);
                }
            }
        }
        _ => {
            tracing::warn!(
                "webui TLS not configured — serving plain HTTP on {}. \
                 Configure webui.tls_cert and webui.tls_key for HTTPS.",
                listen_addr
            );
            let state = AppState::from_config(config, args.config.clone(), None);
            write_pid_file();
            install_sighup_handler(state.clone());
            let app = routes::build_router(state.clone());
            serve_http(app, &listen_addr, state.ip_allow.clone(), shutdown_rx, drain_secs).await;
        }
    }
}

/// Write our PID to the webui PID file so the CLI can send SIGHUP.
fn write_pid_file() {
    #[cfg(unix)]
    {
        let pid_file = std::path::PathBuf::from(DEFAULT_WEBUI_PID_FILE);
        if let Some(parent) = pid_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&pid_file, std::process::id().to_string());
        tracing::debug!(path = %pid_file.display(), "wrote webui PID file");
    }
}

/// Spawn a background task that reloads config on SIGHUP.
fn install_sighup_handler(state: AppState) {
    #[cfg(unix)]
    tokio::spawn(async move {
        let mut sig = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::hangup(),
        )
        .expect("failed to register SIGHUP handler");
        loop {
            sig.recv().await;
            tracing::info!("serverwall-webui received SIGHUP, reloading config");
            state.reload_config();
        }
    });
}

/// Spawn a background task that signals graceful shutdown on SIGTERM or Ctrl-C.
fn install_sigterm_handler(shutdown_tx: tokio::sync::watch::Sender<bool>) {
    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("serverwall-webui received SIGTERM");
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("serverwall-webui received Ctrl+C");
            }
        }
        let _ = shutdown_tx.send(true);
    });

    #[cfg(not(unix))]
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("serverwall-webui received Ctrl+C");
        let _ = shutdown_tx.send(true);
    });
}

/// Create a TCP listener with SO_REUSEPORT so a restarted process can bind the
/// same port while the old instance is still draining connections.
///
/// On Unix, checks for systemd socket activation first (LISTEN_FDS / LISTEN_PID
/// env vars). If activated, the socket FD passed by systemd is used directly,
/// giving zero bind gap across service restarts.
async fn create_listener(addr: &str) -> tokio::net::TcpListener {
    // --- Try systemd socket activation (Unix only) ---
    #[cfg(unix)]
    {
        use std::os::unix::io::FromRawFd;

        let listen_pid = std::env::var("LISTEN_PID").ok()
            .and_then(|v| v.parse::<u32>().ok());
        let listen_fds = std::env::var("LISTEN_FDS").ok()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);

        if listen_fds >= 1 && listen_pid == Some(std::process::id()) {
            // SD_LISTEN_FDS_START = 3 (first inherited FD from systemd)
            // SAFETY: systemd guarantees FD 3 is a valid, listening TCP socket.
            let std_listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
            if let Ok(()) = std_listener.set_nonblocking(true) {
                match tokio::net::TcpListener::from_std(std_listener) {
                    Ok(listener) => {
                        tracing::info!(address = %addr, "serverwall-webui using systemd socket activation");
                        return listener;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to convert socket-activated FD, falling back to bind");
                    }
                }
            }
        }
    }

    // --- Fall back to SO_REUSEPORT bind ---
    match bind_reuseport(addr) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("failed to bind webui to {}: {}", addr, e);
            std::process::exit(1);
        }
    }
}

/// Bind with SO_REUSEPORT so a new process can bind the same address while the
/// old one is draining. Falls back to SO_REUSEADDR-only on non-Unix platforms.
fn bind_reuseport(addr: &str) -> anyhow::Result<tokio::net::TcpListener> {
    let sock_addr: std::net::SocketAddr = addr.parse()?;
    let socket = socket2::Socket::new(
        if sock_addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 },
        socket2::Type::STREAM,
        None,
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&sock_addr.into())?;
    socket.listen(1024)?;
    Ok(tokio::net::TcpListener::from_std(std::net::TcpListener::from(socket))?)
}

/// Drain active connections, waiting up to `drain_secs` for them to finish.
async fn drain_connections(active: &Arc<AtomicUsize>, drain_secs: u64, label: &str) {
    if drain_secs == 0 {
        return;
    }
    let remaining = active.load(Ordering::Relaxed);
    if remaining == 0 {
        return;
    }
    tracing::info!(
        remaining,
        drain_timeout_secs = drain_secs,
        "{} draining active connections",
        label,
    );
    let deadline = Instant::now() + Duration::from_secs(drain_secs);
    loop {
        let n = active.load(Ordering::Relaxed);
        if n == 0 {
            tracing::info!("{} connection drain complete", label);
            break;
        }
        if Instant::now() >= deadline {
            tracing::warn!(remaining = n, "{} drain timeout, forcing shutdown", label);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn serve_https(
    app: axum::Router,
    addr: &str,
    tls_lock: Arc<RwLock<TlsAcceptor>>,
    ip_allow: Arc<ArcSwap<IpMatcher>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    drain_secs: u64,
) {
    let listener = create_listener(addr).await;
    let active = Arc::new(AtomicUsize::new(0));

    tracing::info!(address = %addr, "serverwall-webui listening (HTTPS)");
    println!("serverwall-webui listening on https://{}", addr);

    loop {
        tokio::select! {
            biased;

            result = shutdown_rx.changed() => {
                if result.is_ok() && *shutdown_rx.borrow() {
                    tracing::info!("serverwall-webui HTTPS listener shutting down");
                    break;
                }
            }

            result = listener.accept() => {
                let (stream, peer_addr) = match result {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::error!(error = %e, "accept error");
                        continue;
                    }
                };

                // Check IP allowlist before incurring TLS overhead.
                if !ip_allow.load().matches(peer_addr.ip()) {
                    tracing::warn!(peer = %peer_addr, "webui connection rejected by IP allowlist");
                    continue;
                }

                // Read current acceptor (cheap clone of Arc-backed TlsAcceptor)
                let acceptor = tls_lock.read().await.clone();
                let app = app.clone();
                let active = active.clone();
                active.fetch_add(1, Ordering::Relaxed);

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = hyper_util::rt::TokioIo::new(tls_stream);
                            let service = hyper::service::service_fn(move |req| {
                                let mut app = app.clone();
                                async move { app.call(req).await }
                            });
                            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection(io, service)
                            .await
                            {
                                tracing::debug!(error = %e, peer = %peer_addr, "connection error");
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, peer = %peer_addr, "TLS handshake failed");
                        }
                    }
                    active.fetch_sub(1, Ordering::Relaxed);
                });
            }
        }
    }

    drain_connections(&active, drain_secs, "serverwall-webui HTTPS").await;
}

async fn serve_http(
    app: axum::Router,
    addr: &str,
    ip_allow: Arc<ArcSwap<IpMatcher>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    drain_secs: u64,
) {
    let listener = create_listener(addr).await;
    let active = Arc::new(AtomicUsize::new(0));

    tracing::info!(address = %addr, "serverwall-webui listening (HTTP - no TLS)");
    println!("serverwall-webui listening on http://{}", addr);

    loop {
        tokio::select! {
            biased;

            result = shutdown_rx.changed() => {
                if result.is_ok() && *shutdown_rx.borrow() {
                    tracing::info!("serverwall-webui HTTP listener shutting down");
                    break;
                }
            }

            result = listener.accept() => {
                let (stream, peer_addr) = match result {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::error!(error = %e, "accept error");
                        continue;
                    }
                };

                // Check IP allowlist.
                if !ip_allow.load().matches(peer_addr.ip()) {
                    tracing::warn!(peer = %peer_addr, "webui connection rejected by IP allowlist");
                    continue;
                }

                let app = app.clone();
                let active = active.clone();
                active.fetch_add(1, Ordering::Relaxed);

                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let service = hyper::service::service_fn(move |req| {
                        let mut app = app.clone();
                        async move { app.call(req).await }
                    });
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await
                    {
                        tracing::debug!(error = %e, peer = %peer_addr, "connection error");
                    }
                    active.fetch_sub(1, Ordering::Relaxed);
                });
            }
        }
    }

    drain_connections(&active, drain_secs, "serverwall-webui HTTP").await;
}
