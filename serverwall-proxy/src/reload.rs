use std::path::PathBuf;

use serverwall_core::config::load_config;

/// Handles live configuration reloads (e.g., via SIGHUP or filesystem watch)
/// without dropping active connections.
pub struct ReloadHandler {
    config_path: PathBuf,
}

impl ReloadHandler {
    /// Create a new reload handler for the given config file path.
    pub fn new(config_path: PathBuf) -> Self {
        Self { config_path }
    }

    /// Attempt to reload the configuration from disk.
    ///
    /// Returns `Ok(config)` if the configuration is valid, or an error if
    /// parsing or validation fails. The caller is responsible for applying
    /// the new configuration.
    pub fn reload(&self) -> anyhow::Result<serverwall_core::config::schema::ServerWallConfig> {
        tracing::info!(path = %self.config_path.display(), "reloading configuration");
        let config = load_config(&self.config_path)
            .map_err(|e| anyhow::anyhow!("config reload failed: {}", e))?;
        tracing::info!("configuration reloaded successfully");
        Ok(config)
    }

    /// Listen for reload signals in a loop.
    ///
    /// On Unix, this listens for SIGHUP. On other platforms, this is a no-op.
    /// When a signal is received, it calls `reload()` and sends the new config
    /// over the provided channel.
    pub async fn run(
        self,
        config_tx: tokio::sync::watch::Sender<Option<serverwall_core::config::schema::ServerWallConfig>>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        #[cfg(unix)]
        {
            let mut sighup = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup(),
            )
            .expect("failed to register SIGHUP handler");

            loop {
                tokio::select! {
                    _ = sighup.recv() => {
                        match self.reload() {
                            Ok(config) => {
                                let _ = config_tx.send(Some(config));
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "configuration reload failed, keeping current config");
                            }
                        }
                    }
                    result = shutdown_rx.changed() => {
                        if result.is_ok() && *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix platforms, just wait for shutdown
            let _ = shutdown_rx.changed().await;
            let _ = config_tx;
        }
    }
}
