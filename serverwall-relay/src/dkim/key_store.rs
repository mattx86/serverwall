use std::collections::HashMap;
use std::path::PathBuf;

use serverwall_core::config::schema::DkimDomainConfig;

/// Configuration for a single DKIM signing domain (loaded from config).
#[derive(Debug, Clone)]
pub struct DkimDomainEntry {
    pub domain: String,
    pub selector: String,
    pub key_file: PathBuf,
    pub algorithm: String,
}

/// Manages signing keys per domain.
pub struct DkimKeyStore {
    /// Map from domain name to its DKIM configuration.
    domains: HashMap<String, DkimDomainEntry>,
}

impl DkimKeyStore {
    /// Load the key store from configuration entries.
    pub fn new(configs: &[DkimDomainConfig]) -> Self {
        let mut domains = HashMap::new();
        for cfg in configs {
            let entry = DkimDomainEntry {
                domain: cfg.domain.clone(),
                selector: cfg.selector.clone(),
                key_file: cfg.key_file.clone(),
                algorithm: cfg.algorithm.clone(),
            };
            domains.insert(cfg.domain.to_lowercase(), entry);
        }
        Self { domains }
    }

    /// Look up the signing configuration for a sender domain.
    pub fn lookup(&self, domain: &str) -> Option<&DkimDomainEntry> {
        self.domains.get(&domain.to_lowercase())
    }

    /// Return an iterator over all configured domains.
    pub fn domains(&self) -> impl Iterator<Item = &DkimDomainEntry> {
        self.domains.values()
    }
}

impl Default for DkimKeyStore {
    fn default() -> Self {
        Self {
            domains: HashMap::new(),
        }
    }
}
