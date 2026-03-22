use std::path::Path;

use crate::config::loader::load_config;
use crate::config::schema::{
    AntispamConfig, BackendConfig, BackendPoolConfig, BotDetectionConfig, CookieSecurityConfig,
    DkimDomainConfig, DmarcPolicyDomain, DnsblListEntry, FrontendConfig, GeoConfig,
    RateLimitConfig, RelayConfig, SecurityHeadersConfig, SecurityTlsConfig, SpfDomainConfig,
    WafRulesetConfig,
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

/// Replace a backend pool's configuration entirely (preserves the pool name from the URL).
pub fn update_backend_pool(path: &Path, pool_name: &str, mut pool: BackendPoolConfig) -> Result<()> {
    let mut config = load_config(path)?;
    pool.name = pool_name.to_string();
    let idx = config
        .backend_pool
        .iter()
        .position(|p| p.name == pool_name)
        .ok_or_else(|| ServerWallError::Config(format!("backend pool '{}' not found", pool_name)))?;
    config.backend_pool[idx] = pool;
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

// ---------------------------------------------------------------------------
// Antispam allow list
// ---------------------------------------------------------------------------

pub fn add_antispam_allow_ip(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    if !config.antispam.allow.ips.contains(&ip.to_string()) {
        config.antispam.allow.ips.push(ip.to_string());
    }
    write_config_atomic(path, &config)
}

pub fn remove_antispam_allow_ip(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    config.antispam.allow.ips.retain(|x| x != ip);
    write_config_atomic(path, &config)
}

pub fn add_antispam_allow_sender(path: &Path, sender: &str) -> Result<()> {
    let s = sender.to_lowercase();
    let mut config = load_config(path)?;
    if !config.antispam.allow.senders.contains(&s) {
        config.antispam.allow.senders.push(s);
    }
    write_config_atomic(path, &config)
}

pub fn remove_antispam_allow_sender(path: &Path, sender: &str) -> Result<()> {
    let s = sender.to_lowercase();
    let mut config = load_config(path)?;
    config.antispam.allow.senders.retain(|x| x != &s);
    write_config_atomic(path, &config)
}

pub fn add_antispam_allow_domain(path: &Path, domain: &str) -> Result<()> {
    let d = domain.to_lowercase();
    let mut config = load_config(path)?;
    if !config.antispam.allow.sender_domains.contains(&d) {
        config.antispam.allow.sender_domains.push(d);
    }
    write_config_atomic(path, &config)
}

pub fn remove_antispam_allow_domain(path: &Path, domain: &str) -> Result<()> {
    let d = domain.to_lowercase();
    let mut config = load_config(path)?;
    config.antispam.allow.sender_domains.retain(|x| x != &d);
    write_config_atomic(path, &config)
}

// ---------------------------------------------------------------------------
// Antispam block list
// ---------------------------------------------------------------------------

pub fn add_antispam_block_ip(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    if !config.antispam.block.ips.contains(&ip.to_string()) {
        config.antispam.block.ips.push(ip.to_string());
    }
    write_config_atomic(path, &config)
}

pub fn remove_antispam_block_ip(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    config.antispam.block.ips.retain(|x| x != ip);
    write_config_atomic(path, &config)
}

pub fn add_antispam_block_sender(path: &Path, sender: &str) -> Result<()> {
    let s = sender.to_lowercase();
    let mut config = load_config(path)?;
    if !config.antispam.block.senders.contains(&s) {
        config.antispam.block.senders.push(s);
    }
    write_config_atomic(path, &config)
}

pub fn remove_antispam_block_sender(path: &Path, sender: &str) -> Result<()> {
    let s = sender.to_lowercase();
    let mut config = load_config(path)?;
    config.antispam.block.senders.retain(|x| x != &s);
    write_config_atomic(path, &config)
}

pub fn add_antispam_block_domain(path: &Path, domain: &str) -> Result<()> {
    let d = domain.to_lowercase();
    let mut config = load_config(path)?;
    if !config.antispam.block.sender_domains.contains(&d) {
        config.antispam.block.sender_domains.push(d);
    }
    write_config_atomic(path, &config)
}

pub fn remove_antispam_block_domain(path: &Path, domain: &str) -> Result<()> {
    let d = domain.to_lowercase();
    let mut config = load_config(path)?;
    config.antispam.block.sender_domains.retain(|x| x != &d);
    write_config_atomic(path, &config)
}

// ---------------------------------------------------------------------------
// DNSBL zone management
// ---------------------------------------------------------------------------

pub fn add_antispam_dnsbl_zone(path: &Path, zone: DnsblListEntry) -> Result<()> {
    let mut config = load_config(path)?;
    if config.antispam.dnsbl.lists.iter().any(|z| z.zone == zone.zone) {
        return Err(ServerWallError::Config(format!(
            "DNSBL zone '{}' already configured",
            zone.zone
        )));
    }
    config.antispam.dnsbl.lists.push(zone);
    write_config_atomic(path, &config)
}

pub fn remove_antispam_dnsbl_zone(path: &Path, zone_name: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.antispam.dnsbl.lists.len();
    config.antispam.dnsbl.lists.retain(|z| z.zone != zone_name);
    if config.antispam.dnsbl.lists.len() == before {
        return Err(ServerWallError::Config(format!(
            "DNSBL zone '{}' not found",
            zone_name
        )));
    }
    write_config_atomic(path, &config)
}

/// Replace the antispam configuration section entirely.
pub fn set_antispam_config(path: &Path, antispam: AntispamConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.antispam = antispam;
    write_config_atomic(path, &config)
}

/// Add a DMARC policy domain for DNS record publishing.
pub fn add_dmarc_policy_domain(path: &Path, domain: DmarcPolicyDomain) -> Result<()> {
    let mut config = load_config(path)?;
    if config.relay.dmarc_publish.domains.iter().any(|d| d.domain == domain.domain) {
        return Err(ServerWallError::Config(format!(
            "DMARC policy for '{}' already configured",
            domain.domain
        )));
    }
    config.relay.dmarc_publish.domains.push(domain);
    write_config_atomic(path, &config)
}

/// Update a DMARC policy domain.
pub fn update_dmarc_policy_domain(path: &Path, domain_name: &str, mut domain: DmarcPolicyDomain) -> Result<()> {
    let mut config = load_config(path)?;
    domain.domain = domain_name.to_string();
    let idx = config.relay.dmarc_publish.domains.iter().position(|d| d.domain == domain_name)
        .ok_or_else(|| ServerWallError::Config(format!("DMARC policy for '{}' not found", domain_name)))?;
    config.relay.dmarc_publish.domains[idx] = domain;
    write_config_atomic(path, &config)
}

/// Remove a DMARC policy domain by name.
pub fn remove_dmarc_policy_domain(path: &Path, domain: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.relay.dmarc_publish.domains.len();
    config.relay.dmarc_publish.domains.retain(|d| d.domain != domain);
    if config.relay.dmarc_publish.domains.len() == before {
        return Err(ServerWallError::Config(format!("DMARC policy for '{}' not found", domain)));
    }
    write_config_atomic(path, &config)
}

/// Add an SPF domain for DNS record publishing.
pub fn add_spf_domain(path: &Path, domain: SpfDomainConfig) -> Result<()> {
    let mut config = load_config(path)?;
    if config.relay.spf_publish.domains.iter().any(|d| d.domain == domain.domain) {
        return Err(ServerWallError::Config(format!(
            "SPF record for '{}' already configured",
            domain.domain
        )));
    }
    config.relay.spf_publish.domains.push(domain);
    write_config_atomic(path, &config)
}

/// Update an SPF domain.
pub fn update_spf_domain(path: &Path, domain_name: &str, mut domain: SpfDomainConfig) -> Result<()> {
    let mut config = load_config(path)?;
    domain.domain = domain_name.to_string();
    let idx = config.relay.spf_publish.domains.iter().position(|d| d.domain == domain_name)
        .ok_or_else(|| ServerWallError::Config(format!("SPF record for '{}' not found", domain_name)))?;
    config.relay.spf_publish.domains[idx] = domain;
    write_config_atomic(path, &config)
}

/// Remove an SPF domain by name.
pub fn remove_spf_domain(path: &Path, domain: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.relay.spf_publish.domains.len();
    config.relay.spf_publish.domains.retain(|d| d.domain != domain);
    if config.relay.spf_publish.domains.len() == before {
        return Err(ServerWallError::Config(format!("SPF record for '{}' not found", domain)));
    }
    write_config_atomic(path, &config)
}

/// Replace the relay configuration section entirely.
pub fn set_relay_config(path: &Path, relay: RelayConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.relay = relay;
    write_config_atomic(path, &config)
}

// ---------------------------------------------------------------------------
// Security settings
// ---------------------------------------------------------------------------

/// Replace the TLS security sub-section.
pub fn update_security_tls(path: &Path, tls: SecurityTlsConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.tls = tls;
    write_config_atomic(path, &config)
}

/// Replace the GeoIP security sub-section.
pub fn update_security_geo(path: &Path, geo: GeoConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.geo = geo;
    write_config_atomic(path, &config)
}

/// Replace the security headers sub-section.
pub fn update_security_headers(path: &Path, headers: SecurityHeadersConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.headers = headers;
    write_config_atomic(path, &config)
}

/// Replace the bot detection sub-section.
pub fn update_security_bot(path: &Path, bot: BotDetectionConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.bot_detection = bot;
    write_config_atomic(path, &config)
}

/// Replace the cookie security sub-section.
pub fn update_security_cookies(path: &Path, cookies: CookieSecurityConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.cookies = cookies;
    write_config_atomic(path, &config)
}

/// Add a global rate limit rule (deduplicating by name).
pub fn add_security_rate_limit(path: &Path, rule: RateLimitConfig) -> Result<()> {
    let mut config = load_config(path)?;
    if config.security.rate_limit.iter().any(|r| r.name == rule.name) {
        return Err(ServerWallError::Config(format!(
            "rate limit rule '{}' already exists",
            rule.name
        )));
    }
    config.security.rate_limit.push(rule);
    write_config_atomic(path, &config)
}

/// Remove a global rate limit rule by name.
pub fn remove_security_rate_limit(path: &Path, name: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.security.rate_limit.len();
    config.security.rate_limit.retain(|r| r.name != name);
    if config.security.rate_limit.len() == before {
        return Err(ServerWallError::Config(format!(
            "rate limit rule '{}' not found",
            name
        )));
    }
    write_config_atomic(path, &config)
}
