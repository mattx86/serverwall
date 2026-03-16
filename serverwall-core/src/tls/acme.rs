use std::path::PathBuf;

use crate::config::AcmeConfig;

/// Manages automatic certificate provisioning via the ACME protocol.
pub struct AcmeManager {
    /// Whether ACME is enabled.
    enabled: bool,
    /// Directory URL for the ACME provider.
    directory_url: String,
    /// Contact email for the ACME account.
    email: Option<String>,
    /// Local path where certificates are stored.
    storage_dir: PathBuf,
}

impl AcmeManager {
    /// Create a new ACME manager from configuration.
    pub fn new(config: &AcmeConfig) -> Self {
        Self {
            enabled: config.enabled,
            directory_url: config.directory_url.clone(),
            email: config.email.clone(),
            storage_dir: config.storage_dir.clone(),
        }
    }

    /// Check whether ACME is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Begin the certificate provisioning loop (placeholder).
    pub async fn run(&self) -> crate::error::Result<()> {
        if !self.enabled {
            tracing::info!("ACME is disabled, skipping");
            return Ok(());
        }
        // TODO: implement ACME order flow using instant-acme
        tracing::warn!("ACME run loop is not yet implemented");
        Ok(())
    }
}
