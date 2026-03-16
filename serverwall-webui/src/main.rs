mod state;
mod middleware;
mod static_files;
mod routes;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

use serverwall_core::config::load_config;
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

    if !config.webui.enabled {
        tracing::info!("webui disabled in config (webui.enabled = false), exiting");
        return;
    }

    let listen_addr = config.webui.listen.clone();
    let tls_cert = config.webui.tls_cert.clone();
    let tls_key = config.webui.tls_key.clone();

    let state = AppState::from_config(config, args.config.clone());
    let app = routes::build_router(state);

    match (&tls_cert, &tls_key) {
        (Some(cert_path), Some(key_path)) => {
            match load_rustls_config(cert_path, key_path) {
                Ok(tls_config) => {
                    serve_https(app, &listen_addr, tls_config).await;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to load TLS cert/key for webui, falling back to plain HTTP"
                    );
                    serve_http(app, &listen_addr).await;
                }
            }
        }
        _ => {
            tracing::warn!(
                "webui TLS not configured — serving plain HTTP on {}. \
                 Configure webui.tls_cert and webui.tls_key for HTTPS.",
                listen_addr
            );
            serve_http(app, &listen_addr).await;
        }
    }
}

fn load_rustls_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<ServerConfig> {
    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("failed to open cert {}: {}", cert_path.display(), e))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| anyhow::anyhow!("failed to open key {}: {}", key_path.display(), e))?;

    let mut cert_reader = std::io::BufReader::new(cert_file);
    let mut key_reader = std::io::BufReader::new(key_file);

    let cert_chain: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse cert: {}", e))?;

    let key: PrivateKeyDer<'static> = private_key(&mut key_reader)
        .map_err(|e| anyhow::anyhow!("failed to parse private key: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?;

    Ok(config)
}

async fn serve_https(app: axum::Router, addr: &str, tls_config: ServerConfig) {
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
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

        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper::service::service_fn(move |req| {
                        let app = app.clone();
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
