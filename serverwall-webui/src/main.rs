mod state;
mod middleware;
mod static_files;
mod tls;
mod routes;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing_subscriber::EnvFilter;

use serverwall_core::config::{editor, load_config, schema::{WafExclusions, WafMode, WafRulesetConfig}};
use serverwall_core::DEFAULT_CONFIG_PATH;
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

    // Initialize tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    // Load config
    let config = match load_config(&args.config) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                error = %e,
                config = %args.config.display(),
                "failed to load config, using defaults"
            );
            serverwall_core::config::ServerWallConfig::default()
        }
    };

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

    match (&tls_cert, &tls_key) {
        (Some(cert_path), Some(key_path)) => {
            match tls::load_tls_config(cert_path, key_path) {
                Ok(tls_config) => {
                    let tls_lock = Arc::new(RwLock::new(
                        TlsAcceptor::from(Arc::new(tls_config))
                    ));
                    let state = AppState::from_config(config, args.config.clone(), Some(tls_lock.clone()));
                    let app = routes::build_router(state);
                    serve_https(app, &listen_addr, tls_lock).await;
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
            let app = routes::build_router(state);
            serve_http(app, &listen_addr).await;
        }
    }
}

async fn serve_https(app: axum::Router, addr: &str, tls_lock: Arc<RwLock<TlsAcceptor>>) {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to bind webui to {}: {}", addr, e);
            std::process::exit(1);
        });

    tracing::info!(address = %addr, "serverwall-webui listening (HTTPS)");
    println!("serverwall-webui listening on https://{}", addr);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(error = %e, "accept error");
                continue;
            }
        };

        // Read current acceptor (cheap clone of Arc-backed TlsAcceptor)
        let acceptor = tls_lock.read().await.clone();
        let app = app.clone();

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
        });
    }
}

async fn serve_http(app: axum::Router, addr: &str) {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to bind webui to {}: {}", addr, e);
            std::process::exit(1);
        });

    tracing::info!(address = %addr, "serverwall-webui listening (HTTP - no TLS)");
    println!("serverwall-webui listening on http://{}", addr);

    axum::serve(listener, app).await.expect("server error");
}
