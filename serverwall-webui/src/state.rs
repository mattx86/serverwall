use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use tokio::sync::Mutex;

use serverwall_core::config::ServerWallConfig;
use serverwall_relay::queue::FilesystemSpool;
use serverwall_relay::status::QueueStats;

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
}

impl AppState {
    pub fn from_config(config: ServerWallConfig, config_path: PathBuf) -> Self {
        let spool_dir = config.relay.spool_dir.clone();
        let spool = FilesystemSpool::new(spool_dir)
            .unwrap_or_else(|_| {
                FilesystemSpool::new(PathBuf::from("/tmp/serverwall-spool"))
                    .expect("failed to create fallback spool directory")
            });

        Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            config_path,
            spool: Arc::new(spool),
            queue_stats: Arc::new(Mutex::new(QueueStats::default())),
            started_at: Instant::now(),
            jwt_secret: generate_jwt_secret(),
        }
    }

    /// Re-read the config file from disk and update the in-memory ArcSwap.
    pub fn reload_config(&self) {
        match serverwall_core::config::load_config(&self.config_path) {
            Ok(cfg) => {
                self.config.store(Arc::new(cfg));
                tracing::info!("webui: in-memory config reloaded from disk");
            }
            Err(e) => {
                tracing::warn!(error = %e, "webui: failed to reload config from disk");
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
