use std::path::Path;

use crate::config::loader::load_config;
use crate::config::schema::{
    AntispamConfig, BackendConfig, BackendPoolConfig, DkimDomainConfig, FrontendConfig,
    RelayConfig, WafRulesetConfig,
};
use crate::config::writer::write_config_atomic;
use crate::error::{Result, ServerWallError};

/// Add a frontend to the configuration.
///
/// Fails if a frontend with the same name already exists.
pub fn add_frontend(path: &Path, frontend: FrontendConfig) -> Result<()> {
    let mut config = load_config(path)?;
    if config.frontend.iter().any(|f| f.name == frontend.name) {
        return Err(ServerWallError::Config(format!(
            "frontend '{}' already exists",
            frontend.name
        )));
    }
    config.frontend.push(frontend);
    write_config_atomic(path, &config)
}

/// Remove a frontend by name.
pub fn remove_frontend(path: &Path, name: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.frontend.len();
    config.frontend.retain(|f| f.name != name);
    if config.frontend.len() == before {
        return Err(ServerWallError::Config(format!(
            "frontend '{}' not found",
            name
        )));
    }
    write_config_atomic(path, &config)
}

/// Add a backend pool to the configuration.
pub fn add_backend_pool(path: &Path, pool: BackendPoolConfig) -> Result<()> {
    let mut config = load_config(path)?;
    if config.backend_pool.iter().any(|p| p.name == pool.name) {
        return Err(ServerWallError::Config(format!(
            "backend pool '{}' already exists",
            pool.name
        )));
    }
    config.backend_pool.push(pool);
    write_config_atomic(path, &config)
}

/// Remove a backend pool by name.
pub fn remove_backend_pool(path: &Path, name: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.backend_pool.len();
    config.backend_pool.retain(|p| p.name != name);
    if config.backend_pool.len() == before {
        return Err(ServerWallError::Config(format!(
            "backend pool '{}' not found",
            name
        )));
    }
    write_config_atomic(path, &config)
}

/// Add a backend server to an existing pool.
pub fn add_backend(path: &Path, pool_name: &str, backend: BackendConfig) -> Result<()> {
    let mut config = load_config(path)?;
    let pool = config
        .backend_pool
        .iter_mut()
        .find(|p| p.name == pool_name)
        .ok_or_else(|| {
            ServerWallError::Config(format!("backend pool '{}' not found", pool_name))
        })?;
    if pool.backend.iter().any(|b| b.name == backend.name) {
        return Err(ServerWallError::Config(format!(
            "backend '{}' already exists in pool '{}'",
            backend.name, pool_name
        )));
    }
    pool.backend.push(backend);
    write_config_atomic(path, &config)
}

/// Remove a backend server from a pool.
pub fn remove_backend(path: &Path, pool_name: &str, backend_name: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let pool = config
        .backend_pool
        .iter_mut()
        .find(|p| p.name == pool_name)
        .ok_or_else(|| {
            ServerWallError::Config(format!("backend pool '{}' not found", pool_name))
        })?;
    let before = pool.backend.len();
    pool.backend.retain(|b| b.name != backend_name);
    if pool.backend.len() == before {
        return Err(ServerWallError::Config(format!(
            "backend '{}' not found in pool '{}'",
            backend_name, pool_name
        )));
    }
    write_config_atomic(path, &config)
}

/// Add a WAF ruleset.
pub fn add_waf_ruleset(path: &Path, ruleset: WafRulesetConfig) -> Result<()> {
    let mut config = load_config(path)?;
    if config.waf_ruleset.iter().any(|r| r.name == ruleset.name) {
        return Err(ServerWallError::Config(format!(
            "WAF ruleset '{}' already exists",
            ruleset.name
        )));
    }
    config.waf_ruleset.push(ruleset);
    write_config_atomic(path, &config)
}

/// Remove a WAF ruleset by name.
pub fn remove_waf_ruleset(path: &Path, name: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.waf_ruleset.len();
    config.waf_ruleset.retain(|r| r.name != name);
    if config.waf_ruleset.len() == before {
        return Err(ServerWallError::Config(format!(
            "WAF ruleset '{}' not found",
            name
        )));
    }
    write_config_atomic(path, &config)
}

/// Add a DKIM signing domain to the relay configuration.
pub fn add_dkim_domain(path: &Path, domain: DkimDomainConfig) -> Result<()> {
    let mut config = load_config(path)?;
    if config
        .relay
        .dkim
        .domains
        .iter()
        .any(|d| d.domain == domain.domain)
    {
        return Err(ServerWallError::Config(format!(
            "DKIM domain '{}' already configured",
            domain.domain
        )));
    }
    config.relay.dkim.domains.push(domain);
    write_config_atomic(path, &config)
}

/// Remove a DKIM signing domain by domain name.
pub fn remove_dkim_domain(path: &Path, domain: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.relay.dkim.domains.len();
    config.relay.dkim.domains.retain(|d| d.domain != domain);
    if config.relay.dkim.domains.len() == before {
        return Err(ServerWallError::Config(format!(
            "DKIM domain '{}' not found",
            domain
        )));
    }
    write_config_atomic(path, &config)
}

/// Add an IP to the global ACL allow list.
pub fn add_acl_allow(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    if !config.security.acl.ip.allow.contains(&ip.to_string()) {
        config.security.acl.ip.allow.push(ip.to_string());
    }
    write_config_atomic(path, &config)
}

/// Add an IP to the global ACL block list.
pub fn add_acl_block(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    if !config.security.acl.ip.block.contains(&ip.to_string()) {
        config.security.acl.ip.block.push(ip.to_string());
    }
    write_config_atomic(path, &config)
}

/// Remove an IP from either ACL list.
pub fn remove_acl_ip(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.acl.ip.allow.retain(|a| a != ip);
    config.security.acl.ip.block.retain(|b| b != ip);
    write_config_atomic(path, &config)
}

/// Replace the antispam configuration section entirely.
pub fn set_antispam_config(path: &Path, antispam: AntispamConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.antispam = antispam;
    write_config_atomic(path, &config)
}

/// Replace the relay configuration section entirely.
pub fn set_relay_config(path: &Path, relay: RelayConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.relay = relay;
    write_config_atomic(path, &config)
}
