use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use tokio::sync::{Mutex, RwLock};
use tokio_rustls::TlsAcceptor;

use serverwall_core::acl::IpMatcher;
use serverwall_core::config::ServerWallConfig;
use serverwall_relay::queue::FilesystemSpool;
use serverwall_relay::status::QueueStats;
use serverwall_waf::{RequestLimits, WafEngine};

/// Shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ArcSwap<ServerWallConfig>>,
    /// Path to serverwall.toml on disk — used for direct config edits.
    pub config_path: PathBuf,
    pub spool: Arc<FilesystemSpool>,
    pub queue_stats: Arc<Mutex<QueueStats>>,
    pub started_at: Instant,
    pub jwt_secret: String,
    /// Live TLS acceptor; wrapped in RwLock so it can be hot-swapped via the API.
    pub tls_acceptor: Option<Arc<RwLock<TlsAcceptor>>>,
    /// WAF engine initialized from the "default" ruleset (or built-in defaults).
    pub waf_engine: Arc<WafEngine>,
    /// Live-swappable IP allowlist for the WebUI.
    pub ip_allow: Arc<ArcSwap<IpMatcher>>,
}

impl AppState {
    pub fn from_config(
        config: ServerWallConfig,
        config_path: PathBuf,
        tls_acceptor: Option<Arc<RwLock<TlsAcceptor>>>,
    ) -> Self {
        let spool_dir = config.relay.spool_dir.clone();
        let spool = FilesystemSpool::new(spool_dir)
            .unwrap_or_else(|_| {
                FilesystemSpool::new(PathBuf::from("/tmp/serverwall-spool"))
                    .expect("failed to create fallback spool directory")
            });

        let ip_allow = {
            let matcher = IpMatcher::new(&config.webui.allow_list)
                .unwrap_or_else(|_| IpMatcher::new(&["0.0.0.0/0".to_string(), "::/0".to_string()]).unwrap());
            Arc::new(ArcSwap::from_pointee(matcher))
        };

        // Build WAF engine from the "default" ruleset in config, or use built-in defaults.
        let waf_engine = {
            let ruleset = config.waf_ruleset.iter().find(|r| r.name == "default");
            let (mode, threshold, paranoia) = match ruleset {
                Some(r) => (waf_mode_convert(r.mode), r.anomaly_threshold, r.paranoia_level),
                None    => (serverwall_waf::WafMode::Blocking, 5, 1),
            };
            Arc::new(WafEngine::with_config(mode, threshold, paranoia, RequestLimits::default()))
        };

        Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            config_path,
            spool: Arc::new(spool),
            queue_stats: Arc::new(Mutex::new(QueueStats::default())),
            started_at: Instant::now(),
            jwt_secret: generate_jwt_secret(),
            tls_acceptor,
            waf_engine,
            ip_allow,
        }
    }

    /// Re-read the config file from disk and update the in-memory ArcSwap.
    ///
    /// Uses `load_config_from_str` (parse only, no validation) so that pre-existing
    /// cross-section issues — e.g. a frontend without a TLS cert that the proxy
    /// owns — never block unrelated webui writes.  Full validation is run *before*
    /// each write instead.
    pub fn reload_config(&self) {
        let raw = match std::fs::read_to_string(&self.config_path) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "webui: failed to read config from disk");
                return;
            }
        };
        match serverwall_core::config::load_config_from_str(&raw) {
            Ok(cfg) => {
                let matcher = IpMatcher::new(&cfg.webui.allow_list)
                    .unwrap_or_else(|_| IpMatcher::new(&["0.0.0.0/0".to_string(), "::/0".to_string()]).unwrap());
                self.config.store(Arc::new(cfg));
                self.ip_allow.store(Arc::new(matcher));
                tracing::info!("webui: in-memory config reloaded from disk");
            }
            Err(e) => {
                tracing::warn!(error = %e, "webui: failed to parse config from disk");
            }
        }
    }

    /// Compute queue stats from spool on demand.
    pub async fn refresh_queue_stats(&self) -> QueueStats {
        let messages = self.spool.list().unwrap_or_default();
        let mut stats = QueueStats::default();
        stats.total = messages.len();
        let now = chrono::Utc::now();
        for msg in &messages {
            match msg.metadata.status {
                serverwall_relay::queue::QueueStatus::Pending => stats.pending += 1,
                serverwall_relay::queue::QueueStatus::Deferred => stats.deferred += 1,
                serverwall_relay::queue::QueueStatus::Held => stats.held += 1,
                serverwall_relay::queue::QueueStatus::Active => stats.active += 1,
            }
            let age = (now - msg.metadata.created).num_seconds().max(0) as u64;
            stats.oldest_message_age_secs = Some(
                stats.oldest_message_age_secs.map_or(age, |prev: u64| prev.max(age)),
            );
        }
        let mut guard = self.queue_stats.lock().await;
        *guard = stats.clone();
        stats
    }
}

fn generate_jwt_secret() -> String {
    uuid::Uuid::new_v4().to_string() + &uuid::Uuid::new_v4().to_string()
}

/// Convert config-schema WafMode to the serverwall-waf engine WafMode.
fn waf_mode_convert(m: serverwall_core::config::schema::WafMode) -> serverwall_waf::WafMode {
    use serverwall_core::config::schema::WafMode as C;
    use serverwall_waf::WafMode as E;
    match m {
        C::Blocking      => E::Blocking,
        C::DetectionOnly => E::DetectionOnly,
        C::Disabled      => E::Disabled,
    }
}
