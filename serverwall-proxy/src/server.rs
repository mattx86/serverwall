use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::server::TlsStream;

use serverwall_core::acl::{AccessControlEngine, GeoEngine};
use serverwall_core::balancer::{IpHash, LeastConnections, LoadBalancer, RoundRobin};
use serverwall_core::config::schema::{
    BalanceMethod, LogFormat, ServerWallConfig, ProtocolType,
};
use serverwall_core::health::HealthChecker;
use serverwall_core::tls::{CertStore, build_tls_acceptor, staple_certified_key};
use serverwall_core::types::{Backend, BackendId};

use serverwall_antispam::lists::{AllowList, BlockList};
use serverwall_antispam::pipeline::AntispamPipeline;
use serverwall_waf::rate_limit::{RateLimiter, RateLimitKey};
use serverwall_antispam::predata::{
    BehaviorCheck, DnsblCheck, DnsblZone, EarlyTalkerCheck, HeloCheck,
    ReverseDnsCheck, ResidentialSenderCheck, SmtpRateLimitCheck, SpfCheck, SpfSeverity,
};
use serverwall_antispam::postdata::{
    AntivirusCheck, ArcCheck, AttachmentCheck, BulkDetectionCheck,
    CharsetCheck, ContentCheck, DkimCheck, DmarcCheck, HeaderAnalysisCheck,
    HtmlAnalysisCheck, RatioAnalysisCheck, ScannerDef, UrlAnalysisCheck,
};
use serverwall_core::config::schema::AntispamConfig;

use serverwall_relay::bounce::BounceGenerator;
use serverwall_relay::delivery::{DeliveryManager, MxResolver, OutboundTls, SmtpSender};
use serverwall_relay::dkim::{DkimKeyStore, DkimSigner};
use serverwall_relay::outbound_policy::{
    OutboundContentPolicy, OutboundPolicyChecker, OutboundRateLimit, RecipientLimit,
    SpfAlignmentCheck,
};
use serverwall_relay::queue::{FilesystemSpool, RetryScheduler};
use serverwall_relay::receiver::SmtpReceiver;
use serverwall_relay::trusted_hosts::TrustedHosts;

use tokio::io::AsyncWriteExt;

use crate::listener::TcpListenerTask;
use crate::listener::TlsListenerTask;
use crate::pipeline::RequestPipeline;
use crate::proxy::HttpProxy;
use crate::proxy::ImapProxy;
use crate::proxy::SmtpProxy;
use crate::proxy::TcpProxy;
use crate::reload::ReloadHandler;

type LogWriter = Arc<tokio::sync::Mutex<tokio::io::BufWriter<tokio::fs::File>>>;

/// Orchestrates all listeners, proxies, and health checkers.
pub struct Server {
    config: ServerWallConfig,
    config_path: std::path::PathBuf,
}

impl Server {
    /// Create a new server from the loaded configuration.
    pub fn from_config(config: ServerWallConfig, config_path: std::path::PathBuf) -> Self {
        Self { config, config_path }
    }

    /// Run the server: set up backends, health checkers, and listeners.
    ///
    /// Reacts to SIGHUP (config reload) by dynamically stopping old listeners
    /// and starting new ones.  Blocks until SIGTERM or Ctrl-C.
    pub async fn run(&self) -> anyhow::Result<()> {
        // Write PID file so that serverwallctl/webui can send SIGHUP for reload
        let pid_file = self.config.global.pid_file
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from(serverwall_core::DEFAULT_PID_FILE));
        if let Some(parent) = pid_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&pid_file, std::process::id().to_string());

        // Process-level shutdown channel — used by relay and health checkers.
        // Only fires on SIGTERM/Ctrl-C, NOT on config reload.
        let (proc_shutdown_tx, proc_shutdown_rx) = watch::channel(false);

        // Start relay daemon (survives config reloads — restating it would risk
        // losing in-flight messages).
        let mut relay_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        if self.config.relay.enabled {
            match build_relay(&self.config.relay, proc_shutdown_rx.clone()) {
                Ok(handles) => relay_tasks.extend(handles),
                Err(e) => tracing::error!(error = %e, "relay startup failed — relay disabled"),
            }
        }

        // Wire up the SIGHUP config reload channel so config changes are applied.
        let (config_tx, mut config_rx) =
            tokio::sync::watch::channel::<Option<ServerWallConfig>>(None);
        {
            let handler = ReloadHandler::new(self.config_path.clone());
            let rx = proc_shutdown_rx.clone();
            tokio::spawn(async move { handler.run(config_tx, rx).await; });
        }

        // Per-frontend shutdown senders + task handles.
        // Key: frontend name; Value: (shutdown_tx, JoinHandle).
        let mut fe_shutdowns: std::collections::HashMap<
            String,
            (watch::Sender<bool>, tokio::task::JoinHandle<()>),
        > = Default::default();

        // Health-checker task handles — aborted and rebuilt on every reload.
        let mut hc_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        // Start listeners for the initial config.
        apply_config(
            &self.config,
            &mut fe_shutdowns,
            &mut hc_tasks,
            proc_shutdown_rx.clone(),
        )
        .await?;

        // Convert the one-shot shutdown signal into a channel so we can
        // select! on it in a loop without consuming the future each iteration.
        let (kill_tx, mut kill_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            wait_for_shutdown_signal().await;
            let _ = kill_tx.send(());
        });

        // Main event loop: config reload vs process shutdown.
        loop {
            tokio::select! {
                biased;

                // Process shutdown (SIGTERM / Ctrl-C)
                _ = &mut kill_rx => {
                    tracing::info!("shutdown signal received, stopping all listeners");
                    for (name, (tx, _)) in fe_shutdowns.drain() {
                        let _ = tx.send(true);
                        tracing::debug!(frontend = %name, "listener shutdown signal sent");
                    }
                    for task in hc_tasks.drain(..) { task.abort(); }
                    break;
                }

                // Config reload (SIGHUP)
                result = config_rx.changed() => {
                    if result.is_err() { break; }
                    let new_config = {
                        let borrowed = config_rx.borrow_and_update();
                        match borrowed.as_ref() {
                            Some(c) => c.clone(),
                            None => continue,
                        }
                    };
                    tracing::info!("applying reloaded configuration to proxy listeners");

                    // Stop all current frontend listeners and wait for them to
                    // fully exit so their ports are released before rebinding.
                    let mut old_handles = Vec::new();
                    for (name, (tx, handle)) in fe_shutdowns.drain() {
                        let _ = tx.send(true);
                        tracing::info!(frontend = %name, "listener stopped for reload");
                        old_handles.push(handle);
                    }
                    for task in hc_tasks.drain(..) { task.abort(); }
                    for h in old_handles { let _ = h.await; }

                    // Apply the new config.
                    if let Err(e) = apply_config(
                        &new_config,
                        &mut fe_shutdowns,
                        &mut hc_tasks,
                        proc_shutdown_rx.clone(),
                    )
                    .await
                    {
                        tracing::error!(
                            error = %e,
                            "config reload failed; some listeners may not be running",
                        );
                    }
                }
            }
        }

        // Shut down relay.
        let _ = proc_shutdown_tx.send(true);
        for task in relay_tasks { let _ = task.await; }

        tracing::info!("server stopped");
        Ok(())
    }
}

/// Build backend pools, start health checkers, and spawn all frontend listeners
/// from the given configuration.
///
/// On first call `fe_shutdowns` and `hc_tasks` are empty (startup).
/// On reload the caller has already drained both before calling this.
async fn apply_config(
    config: &ServerWallConfig,
    fe_shutdowns: &mut std::collections::HashMap<
        String,
        (watch::Sender<bool>, tokio::task::JoinHandle<()>),
    >,
    hc_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    proc_shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let pools = build_backend_pools(config);

    // Start health checkers for each pool (use proc_shutdown_rx so they
    // keep running across config reloads and only stop on process exit).
    for pool_config in &config.backend_pool {
        if let Some(backends) = pools.get(&pool_config.name) {
            let checker = HealthChecker::new(backends.clone(), pool_config);
            let rx = proc_shutdown_rx.clone();
            hc_tasks.push(tokio::spawn(async move { checker.run(rx).await; }));
        }
    }

    tracing::info!(
        frontends = config.frontend.len(),
        pools = config.backend_pool.len(),
        "starting proxy listeners",
    );

    // Build geo engine (shared across frontends in this config generation).
    let geo_engine: Option<Arc<GeoEngine>> =
        GeoEngine::from_config(&config.security.geo).map(Arc::new);

    // Build the global IP ACL.
    let global_ip_acl: Option<Arc<AccessControlEngine>> = {
        let ip = &config.security.acl.ip;
        if ip.allow.is_empty() && ip.block.is_empty() {
            None
        } else {
            match AccessControlEngine::from_global_ip(ip) {
                Ok(engine) => Some(Arc::new(engine)),
                Err(e) => {
                    tracing::warn!(error = %e, "global IP ACL parse error — global ACL disabled");
                    None
                }
            }
        }
    };

    // Build HTTP rate limiters.
    let rate_limiters: Vec<Arc<(RateLimiter, RateLimitKey)>> = config
        .security
        .rate_limit
        .iter()
        .map(|r| {
            let limiter = RateLimiter::with_limits(r.requests, r.window_secs);
            let key = RateLimitKey::from_str(&r.key);
            Arc::new((limiter, key))
        })
        .collect();

    // Spawn a listener for each frontend.
    for frontend in &config.frontend {
        let pool_backends = pools
            .get(&frontend.backend_pool)
            .cloned()
            .unwrap_or_default();

        let balancer = build_balancer(frontend.balancer);

        let acl = AccessControlEngine::from_config(&frontend.acl)
            .map_err(|e| anyhow::anyhow!("ACL config error in frontend '{}': {}", frontend.name, e))?;

        // Resolve geo engine: prefer security-profile override, fall back to global.
        let frontend_geo: Option<Arc<GeoEngine>> =
            if let Some(ref pname) = frontend.security_profile {
                if let Some(p) = config.security_profiles.iter().find(|p| p.name == *pname) {
                    GeoEngine::from_config(&p.geo).map(Arc::new).or_else(|| geo_engine.clone())
                } else {
                    geo_engine.clone()
                }
            } else {
                geo_engine.clone()
            };

        let pipeline = Arc::new(RequestPipeline::new(
            acl,
            global_ip_acl.clone(),
            frontend_geo,
            balancer,
            pool_backends,
            config.security.tls.backend_tls_verify,
            config.security.tls.backend_ca_bundle.clone(),
        ));

        // Per-frontend shutdown channel.
        let (fe_tx, fe_rx) = watch::channel(false);

        let handle = match frontend.protocol {
            ProtocolType::Tcp => {
                // Resolve log settings (profile takes precedence for format/access_log;
                // log_file always comes from the frontend directly).
                let (eff_log_format, eff_access_log, eff_log_file) =
                    if let Some(ref pname) = frontend.log_profile {
                        match config.log_profiles.iter().find(|p| p.name == *pname) {
                            Some(p) => (p.format, p.access_log, frontend.log_file.clone()),
                            None => {
                                tracing::warn!(
                                    frontend = %frontend.name,
                                    profile  = %pname,
                                    "log profile not found; falling back to inline settings",
                                );
                                (frontend.log_format, frontend.access_log, frontend.log_file.clone())
                            }
                        }
                    } else {
                        (frontend.log_format, frontend.access_log, frontend.log_file.clone())
                    };

                let tcp_log_writer: Option<LogWriter> = if eff_access_log {
                    if let Some(ref path) = eff_log_file {
                        match tokio::fs::OpenOptions::new()
                            .create(true).append(true).open(path).await
                        {
                            Ok(file) => Some(Arc::new(tokio::sync::Mutex::new(
                                tokio::io::BufWriter::new(file),
                            ))),
                            Err(e) => {
                                tracing::warn!(
                                    frontend = %frontend.name,
                                    path = %path,
                                    error = %e,
                                    "cannot open access log file — logging disabled for this frontend",
                                );
                                None
                            }
                        }
                    } else { None }
                } else { None };

                // If TLS cert fields are set, terminate TLS before proxying.
                if frontend.tls_cert.is_some() || frontend.tls_pfx.is_some() {
                    let cert_store = Arc::new(CertStore::new());
                    let certified_key = CertStore::load_from_frontend(frontend)
                        .map_err(|e| anyhow::anyhow!("TLS error in TCP frontend '{}': {}", frontend.name, e))?;
                    cert_store.add_from_cert(certified_key.clone());
                    cert_store.set_default(certified_key);
                    let acceptor = build_tls_acceptor(cert_store, &frontend.tls_min_version)
                        .map_err(|e| anyhow::anyhow!("TLS acceptor error in frontend '{}': {}", frontend.name, e))?;
                    let listener = TlsListenerTask::new(
                        frontend.listen.clone(),
                        frontend.name.clone(),
                        frontend.max_connections,
                        acceptor,
                    );
                    let frontend_name = frontend.name.clone();
                    let p = pipeline.clone();
                    tokio::spawn(async move {
                        if let Err(e) = run_tls_tcp_frontend(listener, p, &frontend_name, tcp_log_writer, eff_log_format, fe_rx).await {
                            tracing::error!(frontend = %frontend_name, error = %e, "TLS TCP frontend failed");
                        }
                    })
                } else {
                    // Plain TCP passthrough.
                    let listener = TcpListenerTask::new(
                        frontend.listen.clone(),
                        frontend.name.clone(),
                        frontend.max_connections,
                    );
                    let frontend_name = frontend.name.clone();
                    let p = pipeline.clone();
                    tokio::spawn(async move {
                        if let Err(e) = run_tcp_frontend(listener, p, &frontend_name, tcp_log_writer, eff_log_format, fe_rx).await {
                            tracing::error!(frontend = %frontend_name, error = %e, "TCP frontend failed");
                        }
                    })
                }
            }
            ProtocolType::Imaps => {
                let cert_store = Arc::new(CertStore::new());
                let certified_key = CertStore::load_from_frontend(frontend)
                    .map_err(|e| anyhow::anyhow!("TLS error in frontend '{}': {}", frontend.name, e))?;
                cert_store.add_from_cert(certified_key.clone());
                cert_store.set_default(certified_key);
                let acceptor = build_tls_acceptor(cert_store, &frontend.tls_min_version)
                    .map_err(|e| anyhow::anyhow!("TLS acceptor error in frontend '{}': {}", frontend.name, e))?;
                let listener = TlsListenerTask::new(
                    frontend.listen.clone(),
                    frontend.name.clone(),
                    frontend.max_connections,
                    acceptor,
                );
                let frontend_name = frontend.name.clone();
                let p = pipeline.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_imap_frontend(listener, p, &frontend_name, fe_rx).await {
                        tracing::error!(frontend = %frontend_name, error = %e, "IMAP frontend failed");
                    }
                })
            }
            ProtocolType::Https => {
                let cert_store = Arc::new(CertStore::new());
                let certified_key = CertStore::load_from_frontend(frontend)
                    .map_err(|e| anyhow::anyhow!("TLS error in frontend '{}': {}", frontend.name, e))?;

                // Resolve TLS policy: security_profile overrides global security.tls.
                let (eff_hsts_max_age, eff_hsts_subdomains, eff_ocsp, eff_min_version) =
                    if let Some(ref pname) = frontend.security_profile {
                        match config.security_profiles.iter().find(|p| p.name == *pname) {
                            Some(p) => (p.hsts_max_age, p.hsts_include_subdomains, p.ocsp_stapling, p.min_version.clone()),
                            None => {
                                tracing::warn!(
                                    frontend = %frontend.name,
                                    profile  = %pname,
                                    "security profile not found; falling back to global TLS settings",
                                );
                                (
                                    config.security.tls.hsts_max_age,
                                    config.security.tls.hsts_include_subdomains,
                                    config.security.tls.ocsp_stapling,
                                    frontend.tls_min_version.clone(),
                                )
                            }
                        }
                    } else {
                        (
                            config.security.tls.hsts_max_age,
                            config.security.tls.hsts_include_subdomains,
                            config.security.tls.ocsp_stapling,
                            frontend.tls_min_version.clone(),
                        )
                    };

                let certified_key = if eff_ocsp {
                    staple_certified_key(certified_key).await
                } else {
                    certified_key
                };

                cert_store.add_from_cert(certified_key.clone());
                cert_store.set_default(certified_key);

                let acceptor = build_tls_acceptor(cert_store, &eff_min_version)
                    .map_err(|e| anyhow::anyhow!("TLS acceptor error in frontend '{}': {}", frontend.name, e))?;

                let tls_listener = TlsListenerTask::new(
                    frontend.listen.clone(),
                    frontend.name.clone(),
                    frontend.max_connections,
                    acceptor,
                );

                // Resolve security settings from profile or globals.
                let (eff_waf_enabled, eff_waf_ruleset, eff_headers, eff_cookies, eff_bot) =
                    if let Some(ref profile_name) = frontend.security_profile {
                        match config.security_profiles.iter().find(|p| p.name == *profile_name) {
                            Some(p) => (
                                p.waf_enabled,
                                p.waf_ruleset.clone(),
                                p.headers.clone(),
                                p.cookies.clone(),
                                p.bot_detection.clone(),
                            ),
                            None => {
                                tracing::warn!(
                                    frontend = %frontend.name,
                                    profile  = %profile_name,
                                    "security profile not found; falling back to global settings",
                                );
                                (
                                    frontend.waf_enabled,
                                    frontend.waf_ruleset.clone(),
                                    config.security.headers.clone(),
                                    config.security.cookies.clone(),
                                    config.security.bot_detection.clone(),
                                )
                            }
                        }
                    } else {
                        (
                            frontend.waf_enabled,
                            frontend.waf_ruleset.clone(),
                            config.security.headers.clone(),
                            config.security.cookies.clone(),
                            config.security.bot_detection.clone(),
                        )
                    };

                let waf = if eff_waf_enabled && config.security.enabled {
                    let engine = if let Some(ref ruleset_name) = eff_waf_ruleset {
                        config
                            .waf_ruleset
                            .iter()
                            .find(|r| &r.name == ruleset_name)
                            .map(|r| serverwall_waf::WafEngine::from_ruleset_config(r))
                            .unwrap_or_else(|| {
                                tracing::warn!(
                                    frontend = %frontend.name,
                                    ruleset = %ruleset_name,
                                    "WAF ruleset not found, using defaults",
                                );
                                serverwall_waf::WafEngine::new(serverwall_waf::WafMode::Blocking)
                            })
                    } else {
                        serverwall_waf::WafEngine::new(serverwall_waf::WafMode::Blocking)
                    };
                    Some(std::sync::Arc::new(engine))
                } else {
                    None
                };

                let path_acl = {
                    let acl = serverwall_core::acl::PathAcl::from_config(
                        &config.security.acl.path_patterns,
                    );
                    if acl.is_empty() { None } else { Some(Arc::new(acl)) }
                };

                let (eff_log_format, eff_access_log, eff_log_file) =
                    if let Some(ref pname) = frontend.log_profile {
                        match config.log_profiles.iter().find(|p| p.name == *pname) {
                            Some(p) => (p.format, p.access_log, frontend.log_file.clone()),
                            None => {
                                tracing::warn!(
                                    frontend = %frontend.name,
                                    profile  = %pname,
                                    "log profile not found; falling back to inline settings",
                                );
                                (frontend.log_format, frontend.access_log, frontend.log_file.clone())
                            }
                        }
                    } else {
                        (frontend.log_format, frontend.access_log, frontend.log_file.clone())
                    };

                let log_writer: Option<Arc<tokio::sync::Mutex<tokio::io::BufWriter<tokio::fs::File>>>> =
                    if eff_access_log {
                        if let Some(ref path) = eff_log_file {
                            match tokio::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(path)
                                .await
                            {
                                Ok(file) => Some(Arc::new(tokio::sync::Mutex::new(
                                    tokio::io::BufWriter::new(file),
                                ))),
                                Err(e) => {
                                    tracing::warn!(
                                        frontend = %frontend.name,
                                        path = %path,
                                        error = %e,
                                        "cannot open access log file — logging disabled for this frontend",
                                    );
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                let http_proxy = Arc::new(HttpProxy::new(
                    frontend.clone(),
                    eff_headers,
                    waf,
                    pipeline.clone(),
                    path_acl,
                    eff_bot,
                    eff_hsts_max_age,
                    eff_hsts_subdomains,
                    rate_limiters.clone(),
                    eff_cookies,
                    log_writer,
                    eff_log_format,
                    config.security.acl.acl_bypass_waf,
                    config.security.acl.domain.allow.clone(),
                    config.security.acl.domain.block.clone(),
                ));

                let frontend_name = frontend.name.clone();
                let p = pipeline.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_https_frontend(tls_listener, p, http_proxy, &frontend_name, fe_rx).await {
                        tracing::error!(frontend = %frontend_name, error = %e, "HTTPS frontend failed");
                    }
                })
            }
            ProtocolType::Smtps => {
                let cert_store = Arc::new(CertStore::new());
                let certified_key = CertStore::load_from_frontend(frontend)
                    .map_err(|e| anyhow::anyhow!("TLS error in frontend '{}': {}", frontend.name, e))?;
                cert_store.add_from_cert(certified_key.clone());
                cert_store.set_default(certified_key);
                let acceptor = build_tls_acceptor(cert_store, &frontend.tls_min_version)
                    .map_err(|e| anyhow::anyhow!("TLS acceptor error in frontend '{}': {}", frontend.name, e))?;
                let listener = TlsListenerTask::new(
                    frontend.listen.clone(),
                    frontend.name.clone(),
                    frontend.max_connections,
                    acceptor,
                );
                let frontend_name = frontend.name.clone();
                let smtp_headers = frontend.smtp_headers.clone();
                let p = pipeline.clone();
                let effective_antispam: std::borrow::Cow<AntispamConfig> =
                    resolve_antispam_for_profile(
                        &config.antispam,
                        frontend.security_profile.as_deref(),
                        &config.security_profiles,
                    );
                let antispam_pipeline = build_antispam_pipeline(&effective_antispam);
                let allow_list = build_allow_list(&config.antispam);
                let block_list = build_block_list(&config.antispam);
                let hostname = config.global.daemon_name.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_smtps_frontend(
                        listener, p, antispam_pipeline, allow_list, block_list,
                        hostname, &frontend_name, smtp_headers, fe_rx,
                    ).await {
                        tracing::error!(frontend = %frontend_name, error = %e, "SMTPS frontend failed");
                    }
                })
            }
            ProtocolType::SmtpStarttls => {
                let listener = TcpListenerTask::new(
                    frontend.listen.clone(),
                    frontend.name.clone(),
                    frontend.max_connections,
                );
                let frontend_name = frontend.name.clone();
                let smtp_headers = frontend.smtp_headers.clone();
                let p = pipeline.clone();
                let effective_antispam: std::borrow::Cow<AntispamConfig> =
                    resolve_antispam_for_profile(
                        &config.antispam,
                        frontend.security_profile.as_deref(),
                        &config.security_profiles,
                    );
                let antispam_pipeline = build_antispam_pipeline(&effective_antispam);
                let allow_list = build_allow_list(&config.antispam);
                let block_list = build_block_list(&config.antispam);
                let hostname = config.global.daemon_name.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_smtp_starttls_frontend(
                        listener, p, antispam_pipeline, allow_list, block_list,
                        hostname, &frontend_name, smtp_headers, fe_rx,
                    ).await {
                        tracing::error!(frontend = %frontend_name, error = %e, "SMTP-STARTTLS frontend failed");
                    }
                })
            }
        };

        fe_shutdowns.insert(frontend.name.clone(), (fe_tx, handle));
    }

    Ok(())
}

/// Write a single TCP session line to the access log file.
async fn write_tcp_access_log(
    log_writer: &Arc<Option<LogWriter>>,
    log_format: LogFormat,
    client: &SocketAddr,
    backend_tag: &str,
    bytes_in: u64,
    bytes_out: u64,
    duration_secs: f64,
) {
    if let Some(ref writer) = **log_writer {
        let line = match log_format {
            LogFormat::Json => format!(
                "{{\"time\":\"{}\",\"client\":\"{}\",\"backend\":\"{}\",\"bytes_in\":{},\"bytes_out\":{},\"duration_secs\":{:.3}}}\n",
                chrono::Utc::now().to_rfc3339(),
                client,
                backend_tag,
                bytes_in,
                bytes_out,
                duration_secs,
            ),
            _ => format!(
                "{} - - [{}] \"TCP CONNECT {}\" - {}\n",
                client.ip(),
                chrono::Local::now().format("%d/%b/%Y:%H:%M:%S %z"),
                backend_tag,
                bytes_in + bytes_out,
            ),
        };
        let mut w = writer.lock().await;
        let _ = w.write_all(line.as_bytes()).await;
        let _ = w.flush().await;
    }
}

/// Run a plain TCP frontend: accept connections, check ACL, select backend,
/// and proxy bidirectionally.
async fn run_tcp_frontend(
    listener: TcpListenerTask,
    pipeline: Arc<RequestPipeline>,
    frontend_name: &str,
    log_writer: Option<LogWriter>,
    log_format: LogFormat,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = frontend_name.to_string();
    let log_writer = Arc::new(log_writer);

    listener
        .run(
            move |client_stream: TcpStream, peer_addr: SocketAddr, local_addr: SocketAddr| {
                let pipeline = pipeline.clone();
                let name = name.clone();
                let lw = log_writer.clone();

                async move {
                    handle_tcp_connection(client_stream, peer_addr, local_addr, &pipeline, &name, &lw, log_format)
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
    log_writer: &Arc<Option<LogWriter>>,
    log_format: LogFormat,
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
        match pipeline.connect_backend_tls(&backend).await {
            Ok(tls_stream) => {
                // Proxy with TLS backend
                let start = std::time::Instant::now();
                match TcpProxy::proxy(client_stream, tls_stream).await {
                    Ok((c2b, b2c)) => {
                        let dur = start.elapsed().as_secs_f64();
                        tracing::info!(
                            frontend = %frontend_name,
                            client = %peer_addr,
                            backend_tag = %backend.tag,
                            bytes_in = c2b,
                            bytes_out = b2c,
                            duration_secs = dur,
                            "TCP proxy session completed",
                        );
                        write_tcp_access_log(log_writer, log_format, &peer_addr, &backend.tag, c2b, b2c, dur).await;
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
            let dur = start.elapsed().as_secs_f64();
            tracing::info!(
                frontend = %frontend_name,
                client = %peer_addr,
                backend_tag = %backend.tag,
                bytes_in = c2b,
                bytes_out = b2c,
                duration_secs = dur,
                "TCP proxy session completed",
            );
            write_tcp_access_log(log_writer, log_format, &peer_addr, &backend.tag, c2b, b2c, dur).await;
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

/// Run a TLS-terminating TCP frontend: terminate TLS, then proxy raw bytes.
async fn run_tls_tcp_frontend(
    listener: TlsListenerTask,
    pipeline: Arc<RequestPipeline>,
    frontend_name: &str,
    log_writer: Option<LogWriter>,
    log_format: LogFormat,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = frontend_name.to_string();
    let log_writer = Arc::new(log_writer);

    listener
        .run(
            move |tls_stream: TlsStream<TcpStream>,
                  peer_addr: SocketAddr,
                  _local_addr: SocketAddr,
                  _sni: Option<String>,
                  _ja3: Option<String>| {
                let pipeline = pipeline.clone();
                let name = name.clone();
                let lw = log_writer.clone();

                async move {
                    handle_tls_tcp_connection(tls_stream, peer_addr, &pipeline, &name, &lw, log_format).await;
                }
            },
            shutdown_rx,
        )
        .await
}

/// Handle a single TLS-terminated TCP proxy connection.
async fn handle_tls_tcp_connection(
    client_stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    pipeline: &RequestPipeline,
    frontend_name: &str,
    log_writer: &Arc<Option<LogWriter>>,
    log_format: LogFormat,
) {
    // Check ACL
    if let Err(e) = pipeline.check_acl(peer_addr.ip()) {
        tracing::debug!(
            frontend = %frontend_name,
            client = %peer_addr,
            error = %e,
            "TLS TCP connection denied by ACL",
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

    // Connect to backend (TLS or plain)
    if backend.tls {
        match pipeline.connect_backend_tls(&backend).await {
            Ok(backend_stream) => {
                let start = std::time::Instant::now();
                match TcpProxy::proxy(client_stream, backend_stream).await {
                    Ok((c2b, b2c)) => {
                        let dur = start.elapsed().as_secs_f64();
                        tracing::info!(
                            frontend = %frontend_name,
                            client = %peer_addr,
                            backend_tag = %backend.tag,
                            bytes_in = c2b,
                            bytes_out = b2c,
                            duration_secs = dur,
                            "TLS TCP proxy session completed",
                        );
                        write_tcp_access_log(log_writer, log_format, &peer_addr, &backend.tag, c2b, b2c, dur).await;
                    }
                    Err(e) if e.kind() != std::io::ErrorKind::ConnectionReset
                        && e.kind() != std::io::ErrorKind::BrokenPipe =>
                    {
                        tracing::debug!(
                            frontend = %frontend_name,
                            client = %peer_addr,
                            backend_tag = %backend.tag,
                            error = %e,
                            "TLS TCP proxy I/O error",
                        );
                    }
                    Err(_) => {}
                }
            }
            Err(e) => tracing::warn!(
                frontend = %frontend_name,
                client = %peer_addr,
                backend_tag = %backend.tag,
                error = %e,
                "failed to connect to TLS backend",
            ),
        }
        return;
    }

    let backend_stream = match RequestPipeline::connect_backend(&backend).await {
        Ok(s) => s,
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
    };

    let start = std::time::Instant::now();
    match TcpProxy::proxy(client_stream, backend_stream).await {
        Ok((c2b, b2c)) => {
            let dur = start.elapsed().as_secs_f64();
            tracing::info!(
                frontend = %frontend_name,
                client = %peer_addr,
                backend_tag = %backend.tag,
                bytes_in = c2b,
                bytes_out = b2c,
                duration_secs = dur,
                "TLS TCP proxy session completed",
            );
            write_tcp_access_log(log_writer, log_format, &peer_addr, &backend.tag, c2b, b2c, dur).await;
        }
        Err(e) if e.kind() != std::io::ErrorKind::ConnectionReset
            && e.kind() != std::io::ErrorKind::BrokenPipe =>
        {
            tracing::debug!(
                frontend = %frontend_name,
                client = %peer_addr,
                backend_tag = %backend.tag,
                error = %e,
                "TLS TCP proxy I/O error",
            );
        }
        Err(_) => {}
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
            move |tls_stream, peer_addr, _local_addr, sni, ja3| {
                let pipeline = pipeline.clone();
                let name = name.clone();

                async move {
                    // Check ACL
                    if let Err(e) = pipeline.check_acl(peer_addr.ip()) {
                        tracing::debug!(
                            frontend = %name,
                            client = %peer_addr,
                            sni = sni.as_deref().unwrap_or("-"),
                            ja3 = ja3.as_deref().unwrap_or("-"),
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
                                ja3 = ja3.as_deref().unwrap_or("-"),
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
            move |tls_stream, peer_addr, _local_addr, _sni, ja3| {
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
                        .handle_connection(tls_stream, peer_addr.ip(), ja3)
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

/// Resolve the effective antispam config for an SMTP frontend, applying any
/// per-profile overrides (thresholds, antivirus) on top of the global config.
fn resolve_antispam_for_profile<'a>(
    global: &'a AntispamConfig,
    profile_name: Option<&str>,
    profiles: &'a [serverwall_core::config::schema::SecurityProfile],
) -> std::borrow::Cow<'a, AntispamConfig> {
    if let Some(pname) = profile_name {
        if let Some(p) = profiles.iter().find(|p| p.name == pname) {
            if let Some(ref pa) = p.antispam {
                let mut cfg = global.clone();
                cfg.enabled = pa.enabled;
                if let Some(t) = pa.possible_spam_threshold { cfg.possible_spam_threshold = t; }
                if let Some(t) = pa.definite_spam_threshold { cfg.definite_spam_threshold = t; }
                cfg.antivirus = pa.antivirus.clone();
                return std::borrow::Cow::Owned(cfg);
            }
        }
    }
    std::borrow::Cow::Borrowed(global)
}

/// Build antispam pipeline from config, wiring all enabled checks.
fn build_antispam_pipeline(config: &AntispamConfig) -> Arc<AntispamPipeline> {
    if !config.enabled {
        return Arc::new(AntispamPipeline::empty());
    }

    let mut pre: Vec<Box<dyn serverwall_antispam::pipeline::PreDataCheck>> = Vec::new();
    let mut post: Vec<Box<dyn serverwall_antispam::pipeline::PostDataCheck>> = Vec::new();

    // Pre-data checks
    if config.dnsbl.enabled && !config.dnsbl.lists.is_empty() {
        let zones = config.dnsbl.lists.iter().map(|l| DnsblZone {
            zone: l.zone.clone(),
            weight_multiplier: l.weight_multiplier,
            reject_on_hit: l.reject_on_hit,
        }).collect();
        pre.push(Box::new(DnsblCheck::new(zones, config.dnsbl.weight)));
    }
    if config.spf.enabled {
        let severity = SpfSeverity {
            fail: config.spf.severity.fail,
            softfail: config.spf.severity.softfail,
            neutral: config.spf.severity.neutral,
            none: config.spf.severity.none,
        };
        pre.push(Box::new(SpfCheck::new(config.spf.weight, severity)));
    }
    if config.rdns.enabled {
        pre.push(Box::new(ReverseDnsCheck::new(config.rdns.weight)));
    }
    if config.residential_spf.enabled {
        let c = &config.residential_spf;
        pre.push(Box::new(ResidentialSenderCheck::new(
            c.weight,
            c.reject,
            c.check_pbl,
            c.pbl_zone.clone(),
            c.softfail_triggers,
            c.neutral_triggers,
        )));
    }
    if config.helo.enabled {
        pre.push(Box::new(HeloCheck::new(config.helo.weight)));
    }
    if config.rate_limit.enabled {
        let window = parse_smtp_duration(&config.rate_limit.per_ip.window);
        pre.push(Box::new(SmtpRateLimitCheck::new(
            config.rate_limit.weight,
            config.rate_limit.per_ip.max,
            config.rate_limit.per_domain.max,
            config.rate_limit.per_sender.max,
            window,
        )));
    }
    if config.early_talker.enabled {
        pre.push(Box::new(EarlyTalkerCheck::new(config.early_talker.weight)));
    }
    // BehaviorCheck has no dedicated config section — always include at low weight
    pre.push(Box::new(BehaviorCheck::new(0.5)));

    // Post-data checks
    if config.dkim.enabled {
        post.push(Box::new(DkimCheck::new(config.dkim.weight)));
    }
    // ArcCheck has no dedicated config section — always include at low weight
    post.push(Box::new(ArcCheck::new(0.5)));
    if config.dmarc.enabled {
        post.push(Box::new(DmarcCheck::new(config.dmarc.weight, config.dmarc.honor_reject_policy)));
    }
    if config.content.enabled {
        post.push(Box::new(ContentCheck::new(config.content.weight)));
    }
    if config.url_analysis.enabled {
        post.push(Box::new(UrlAnalysisCheck::new(
            config.url_analysis.weight,
            config.url_analysis.surbl_zones.clone(),
        )));
    }
    if config.attachment.enabled {
        post.push(Box::new(AttachmentCheck::new(
            config.attachment.weight,
            config.attachment.dangerous_extensions.clone(),
        )));
    }
    if config.html.enabled {
        post.push(Box::new(HtmlAnalysisCheck::new(config.html.weight)));
    }
    if config.header_analysis.enabled {
        post.push(Box::new(HeaderAnalysisCheck::new(config.header_analysis.weight)));
    }
    if config.charset.enabled {
        post.push(Box::new(CharsetCheck::new(config.charset.weight)));
    }
    if config.bulk.enabled {
        post.push(Box::new(BulkDetectionCheck::new(config.bulk.weight)));
    }
    if config.ratio.enabled {
        post.push(Box::new(RatioAnalysisCheck::new(config.ratio.weight)));
    }
    if config.antivirus.enabled && !config.antivirus.scanners.is_empty() {
        let scanners = config.antivirus.scanners.iter().map(|s| ScannerDef {
            name: s.name.clone(),
            command: s.command.clone(),
            clean_exit_codes: s.clean_exit_codes.clone(),
            virus_exit_codes: s.virus_exit_codes.clone(),
            virus_name_pattern: s.virus_name_pattern.as_ref()
                .and_then(|p| regex::Regex::new(p).ok()),
        }).collect();
        post.push(Box::new(AntivirusCheck::new(
            config.antivirus.weight,
            config.antivirus.reject_on_virus,
            scanners,
        )));
    }

    Arc::new(AntispamPipeline::new(config.clone(), pre, post))
}

/// Parse a duration string like "5m", "2h", "1d", "30s" → std::time::Duration.
fn parse_smtp_duration(s: &str) -> std::time::Duration {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s').and_then(|n| n.parse::<u64>().ok()) {
        return std::time::Duration::from_secs(n);
    }
    if let Some(n) = s.strip_suffix('m').and_then(|n| n.parse::<u64>().ok()) {
        return std::time::Duration::from_secs(n * 60);
    }
    if let Some(n) = s.strip_suffix('h').and_then(|n| n.parse::<u64>().ok()) {
        return std::time::Duration::from_secs(n * 3600);
    }
    if let Some(n) = s.strip_suffix('d').and_then(|n| n.parse::<u64>().ok()) {
        return std::time::Duration::from_secs(n * 86400);
    }
    std::time::Duration::from_secs(3600) // fallback: 1 hour
}

/// Build allow list from config.
fn build_allow_list(config: &serverwall_core::config::schema::AntispamConfig) -> Arc<AllowList> {
    Arc::new(AllowList::from_config(
        config.allow.ips.clone(),
        config.allow.senders.clone(),
        config.allow.sender_domains.clone(),
    ))
}

/// Build block list from config.
fn build_block_list(config: &serverwall_core::config::schema::AntispamConfig) -> Arc<BlockList> {
    Arc::new(BlockList::from_config(
        config.block.ips.clone(),
        config.block.senders.clone(),
        config.block.sender_domains.clone(),
        config.block.recipients.clone(),
    ))
}

/// Run an SMTPS frontend: immediate TLS termination, then SMTP proxy.
async fn run_smtps_frontend(
    listener: TlsListenerTask,
    pipeline: Arc<RequestPipeline>,
    antispam_pipeline: Arc<AntispamPipeline>,
    allow_list: Arc<AllowList>,
    block_list: Arc<BlockList>,
    hostname: String,
    frontend_name: &str,
    smtp_headers: serverwall_core::config::schema::SmtpHeadersConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = frontend_name.to_string();

    listener
        .run(
            move |tls_stream, peer_addr, _local_addr, _sni, ja3| {
                let pipeline = pipeline.clone();
                let name = name.clone();
                let antispam = antispam_pipeline.clone();
                let wl = allow_list.clone();
                let bl = block_list.clone();
                let host = hostname.clone();
                let smtp_hdrs = smtp_headers.clone();

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
                        ja3.clone(),
                        smtp_hdrs,
                    );

                    match proxy.proxy(tls_stream, peer_addr).await {
                        Ok(result) => {
                            tracing::info!(
                                frontend = %name,
                                client = %peer_addr,
                                backend_tag = %backend.tag,
                                mail_from = %result.mail_from,
                                rcpt_to = %result.rcpt_to.join(", "),
                                verdict = %result.verdict,
                                spam_score = result.spam_score,
                                bytes_in = result.bytes_from_client,
                                bytes_out = result.bytes_from_backend,
                                duration_secs = result.duration_secs,
                                ja3 = ja3.as_deref().unwrap_or("-"),
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
    allow_list: Arc<AllowList>,
    block_list: Arc<BlockList>,
    hostname: String,
    frontend_name: &str,
    smtp_headers: serverwall_core::config::schema::SmtpHeadersConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = frontend_name.to_string();

    listener
        .run(
            move |tcp_stream: TcpStream, peer_addr: SocketAddr, _local_addr: SocketAddr| {
                let pipeline = pipeline.clone();
                let name = name.clone();
                let antispam = antispam_pipeline.clone();
                let wl = allow_list.clone();
                let bl = block_list.clone();
                let smtp_hdrs = smtp_headers.clone();
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
                        None, // No TLS at the listener level for STARTTLS
                        smtp_hdrs,
                    );

                    match proxy.proxy(tcp_stream, peer_addr).await {
                        Ok(result) => {
                            tracing::info!(
                                frontend = %name,
                                client = %peer_addr,
                                backend_tag = %backend.tag,
                                mail_from = %result.mail_from,
                                rcpt_to = %result.rcpt_to.join(", "),
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

/// Build and start the relay daemon: delivery manager + optional inbound SMTP receiver.
fn build_relay(
    config: &serverwall_core::config::schema::RelayConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<Vec<tokio::task::JoinHandle<()>>> {
    let spool = Arc::new(FilesystemSpool::new(config.spool_dir.clone())?);
    let scheduler = Arc::new(RetryScheduler::new(&config.retry));
    let resolver = Arc::new(MxResolver::new()?);
    let hostname = config.hostname.clone().unwrap_or_else(|| "localhost".to_string());
    let tls = OutboundTls::new(&config.tls)?;
    let sender = Arc::new(SmtpSender::new(hostname.clone(), Some(tls)));
    let bounce_gen = Arc::new(BounceGenerator::new(
        config.bounce.sender.clone(),
        config.bounce.include_original_headers,
    ));
    let dkim_key_store = Arc::new(DkimKeyStore::new(&config.dkim.domains));
    let dkim_signer = Arc::new(DkimSigner::new());
    let delivery_manager = Arc::new(DeliveryManager::new(
        spool.clone(),
        scheduler,
        resolver,
        sender,
        bounce_gen,
        config.delivery_threads,
    ));

    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    let dm = delivery_manager.clone();
    let rx = shutdown_rx.clone();
    handles.push(tokio::spawn(async move { dm.run(rx).await }));

    if !config.listen.is_empty() {
        let listen_addrs: Vec<SocketAddr> = config.listen.iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let trusted_hosts = Arc::new(TrustedHosts::new(&config.trusted_hosts));
        let policy = Arc::new(OutboundPolicyChecker {
            rate_limit: OutboundRateLimit::new(
                config.outbound_policy.max_messages_per_domain_per_hour,
            ),
            content_policy: OutboundContentPolicy::new(&config.outbound_policy),
            spf_alignment: SpfAlignmentCheck::new(config.outbound_policy.allowed_sender_domains.clone()),
            recipient_limit: RecipientLimit::new(
                config.outbound_policy.max_recipients_per_message,
            ),
        });
        let receiver = Arc::new(SmtpReceiver::new(
            listen_addrs,
            hostname,
            trusted_hosts,
            spool,
            policy,
            config.dkim.enabled,
            dkim_signer,
            dkim_key_store,
        ));
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = receiver.run(rx).await {
                tracing::error!(error = %e, "relay receiver error");
            }
        }));
    }

    tracing::info!(
        hostname = %config.hostname.as_deref().unwrap_or("localhost"),
        delivery_threads = config.delivery_threads,
        "relay started",
    );
    Ok(handles)
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
