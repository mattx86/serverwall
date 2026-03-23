use std::path::Path;

use crate::config::loader::{load_config, validate_config};
use crate::config::schema::{
    AcmeConfig, AntispamConfig, BackendConfig, BackendPoolConfig, BotDetectionConfig,
    CookieSecurityConfig, DkimDomainConfig, DmarcPolicyDomain, DnsblListEntry, DomainOverride,
    FrontendConfig, GeoConfig, GlobalConfig, LogProfile, RateLimitConfig, RelayConfig,
    ScannerConfig, SecurityHeadersConfig, SecurityProfile, SecurityTlsConfig, SpfDomainConfig,
    TlsProfile, WafRulesetConfig,
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
    validate_config(&config)?;
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
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Replace a frontend's configuration in-place (single atomic write).
/// Fails if no frontend with `name` exists.
pub fn update_frontend(path: &Path, name: &str, mut frontend: FrontendConfig) -> Result<()> {
    let mut config = load_config(path)?;
    frontend.name = name.to_string();
    let idx = config
        .frontend
        .iter()
        .position(|f| f.name == name)
        .ok_or_else(|| ServerWallError::Config(format!("frontend '{}' not found", name)))?;
    config.frontend[idx] = frontend;
    validate_config(&config)?;
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
    validate_config(&config)?;
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
    validate_config(&config)?;
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
    validate_config(&config)?;
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
    validate_config(&config)?;
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
    validate_config(&config)?;
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
    validate_config(&config)?;
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
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Replace a WAF ruleset in-place (single atomic write).
/// Fails if no ruleset with `name` exists.
pub fn update_waf_ruleset(path: &Path, name: &str, mut ruleset: WafRulesetConfig) -> Result<()> {
    let mut config = load_config(path)?;
    ruleset.name = name.to_string();
    let idx = config
        .waf_ruleset
        .iter()
        .position(|r| r.name == name)
        .ok_or_else(|| ServerWallError::Config(format!("WAF ruleset '{}' not found", name)))?;
    config.waf_ruleset[idx] = ruleset;
    validate_config(&config)?;
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
    validate_config(&config)?;
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
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Add an IP to the global ACL allow list.
pub fn add_acl_allow(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    if !config.security.acl.ip.allow.contains(&ip.to_string()) {
        config.security.acl.ip.allow.push(ip.to_string());
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Add an IP to the global ACL block list.
pub fn add_acl_block(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    if !config.security.acl.ip.block.contains(&ip.to_string()) {
        config.security.acl.ip.block.push(ip.to_string());
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Remove an IP from either ACL list.
pub fn remove_acl_ip(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.acl.ip.allow.retain(|a| a != ip);
    config.security.acl.ip.block.retain(|b| b != ip);
    validate_config(&config)?;
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
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_antispam_allow_ip(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    config.antispam.allow.ips.retain(|x| x != ip);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn add_antispam_allow_sender(path: &Path, sender: &str) -> Result<()> {
    let s = sender.to_lowercase();
    let mut config = load_config(path)?;
    if !config.antispam.allow.senders.contains(&s) {
        config.antispam.allow.senders.push(s);
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_antispam_allow_sender(path: &Path, sender: &str) -> Result<()> {
    let s = sender.to_lowercase();
    let mut config = load_config(path)?;
    config.antispam.allow.senders.retain(|x| x != &s);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn add_antispam_allow_domain(path: &Path, domain: &str) -> Result<()> {
    let d = domain.to_lowercase();
    let mut config = load_config(path)?;
    if !config.antispam.allow.sender_domains.contains(&d) {
        config.antispam.allow.sender_domains.push(d);
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_antispam_allow_domain(path: &Path, domain: &str) -> Result<()> {
    let d = domain.to_lowercase();
    let mut config = load_config(path)?;
    config.antispam.allow.sender_domains.retain(|x| x != &d);
    validate_config(&config)?;
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
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_antispam_block_ip(path: &Path, ip: &str) -> Result<()> {
    let mut config = load_config(path)?;
    config.antispam.block.ips.retain(|x| x != ip);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn add_antispam_block_sender(path: &Path, sender: &str) -> Result<()> {
    let s = sender.to_lowercase();
    let mut config = load_config(path)?;
    if !config.antispam.block.senders.contains(&s) {
        config.antispam.block.senders.push(s);
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_antispam_block_sender(path: &Path, sender: &str) -> Result<()> {
    let s = sender.to_lowercase();
    let mut config = load_config(path)?;
    config.antispam.block.senders.retain(|x| x != &s);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn add_antispam_block_domain(path: &Path, domain: &str) -> Result<()> {
    let d = domain.to_lowercase();
    let mut config = load_config(path)?;
    if !config.antispam.block.sender_domains.contains(&d) {
        config.antispam.block.sender_domains.push(d);
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_antispam_block_domain(path: &Path, domain: &str) -> Result<()> {
    let d = domain.to_lowercase();
    let mut config = load_config(path)?;
    config.antispam.block.sender_domains.retain(|x| x != &d);
    validate_config(&config)?;
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
    validate_config(&config)?;
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
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Replace the antispam configuration section entirely.
pub fn set_antispam_config(path: &Path, antispam: AntispamConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.antispam = antispam;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Update antispam check weights and enabled flags without touching lists or zones.
pub fn update_antispam_checks(path: &Path, update: AntispamChecksUpdate) -> Result<()> {
    let mut config = load_config(path)?;
    let a = &mut config.antispam;
    if let Some(v) = update.enabled { a.enabled = v; }
    if let Some(v) = update.possible_spam_threshold { a.possible_spam_threshold = v; }
    if let Some(v) = update.definite_spam_threshold { a.definite_spam_threshold = v; }
    if let Some(v) = update.max_check_duration { a.max_check_duration = v; }
    macro_rules! apply_check {
        ($field:expr, $upd:expr) => {
            if let Some(c) = $upd {
                if let Some(v) = c.enabled { $field.enabled = v; }
                if let Some(v) = c.weight  { $field.weight  = v; }
            }
        };
    }
    apply_check!(a.dnsbl,           update.dnsbl);
    apply_check!(a.spf,             update.spf);
    apply_check!(a.dkim,            update.dkim);
    apply_check!(a.dmarc,           update.dmarc);
    apply_check!(a.rdns,            update.rdns);
    apply_check!(a.helo,            update.helo);
    apply_check!(a.early_talker,    update.early_talker);
    apply_check!(a.content,         update.content);
    apply_check!(a.url_analysis,    update.url_analysis);
    apply_check!(a.attachment,      update.attachment);
    apply_check!(a.html,            update.html);
    apply_check!(a.header_analysis, update.header_analysis);
    apply_check!(a.charset,         update.charset);
    apply_check!(a.bulk,            update.bulk);
    apply_check!(a.ratio,           update.ratio);
    if let Some(c) = update.residential_spf {
        if let Some(v) = c.enabled           { a.residential_spf.enabled           = v; }
        if let Some(v) = c.weight            { a.residential_spf.weight            = v; }
        if let Some(v) = c.reject            { a.residential_spf.reject            = v; }
        if let Some(v) = c.check_pbl         { a.residential_spf.check_pbl         = v; }
        if let Some(v) = c.pbl_zone          { a.residential_spf.pbl_zone          = v; }
        if let Some(v) = c.softfail_triggers { a.residential_spf.softfail_triggers = v; }
        if let Some(v) = c.neutral_triggers  { a.residential_spf.neutral_triggers  = v; }
    }
    if let Some(c) = update.antivirus {
        if let Some(v) = c.enabled             { a.antivirus.enabled             = v; }
        if let Some(v) = c.weight              { a.antivirus.weight              = v; }
        if let Some(v) = c.reject_on_virus     { a.antivirus.reject_on_virus     = v; }
        if let Some(v) = c.on_scanner_error    { a.antivirus.on_scanner_error    = v; }
        if let Some(v) = c.on_scanner_timeout  { a.antivirus.on_scanner_timeout  = v; }
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct AntispamChecksUpdate {
    pub enabled: Option<bool>,
    pub possible_spam_threshold: Option<u8>,
    pub definite_spam_threshold: Option<u8>,
    pub max_check_duration: Option<String>,
    pub dnsbl:            Option<CheckFieldUpdate>,
    pub spf:              Option<CheckFieldUpdate>,
    pub dkim:             Option<CheckFieldUpdate>,
    pub dmarc:            Option<CheckFieldUpdate>,
    pub rdns:             Option<CheckFieldUpdate>,
    pub helo:             Option<CheckFieldUpdate>,
    pub early_talker:     Option<CheckFieldUpdate>,
    pub content:          Option<CheckFieldUpdate>,
    pub url_analysis:     Option<CheckFieldUpdate>,
    pub attachment:       Option<CheckFieldUpdate>,
    pub html:             Option<CheckFieldUpdate>,
    pub header_analysis:  Option<CheckFieldUpdate>,
    pub charset:          Option<CheckFieldUpdate>,
    pub bulk:             Option<CheckFieldUpdate>,
    pub ratio:            Option<CheckFieldUpdate>,
    pub residential_spf:  Option<ResidentialSpfFieldUpdate>,
    pub antivirus:        Option<AntivirusFieldUpdate>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct CheckFieldUpdate {
    pub enabled: Option<bool>,
    pub weight:  Option<f64>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct ResidentialSpfFieldUpdate {
    pub enabled:           Option<bool>,
    pub weight:            Option<f64>,
    pub reject:            Option<bool>,
    pub check_pbl:         Option<bool>,
    pub pbl_zone:          Option<String>,
    pub softfail_triggers: Option<bool>,
    pub neutral_triggers:  Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct AntivirusFieldUpdate {
    pub enabled:            Option<bool>,
    pub weight:             Option<f64>,
    pub reject_on_virus:    Option<bool>,
    pub on_scanner_error:   Option<String>,
    pub on_scanner_timeout: Option<String>,
}

/// Add a SURBL zone to the antispam URL analysis config.
pub fn add_antispam_surbl_zone(path: &Path, zone: String) -> Result<()> {
    let mut config = load_config(path)?;
    if config.antispam.url_analysis.surbl_zones.contains(&zone) {
        return Err(ServerWallError::Config(format!("SURBL zone '{}' already exists", zone)));
    }
    config.antispam.url_analysis.surbl_zones.push(zone);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Remove a SURBL zone from the antispam URL analysis config.
pub fn remove_antispam_surbl_zone(path: &Path, zone: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.antispam.url_analysis.surbl_zones.len();
    config.antispam.url_analysis.surbl_zones.retain(|z| z != zone);
    if config.antispam.url_analysis.surbl_zones.len() == before {
        return Err(ServerWallError::Config(format!("SURBL zone '{}' not found", zone)));
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Add an antivirus scanner to the global antispam antivirus config.
pub fn add_antispam_scanner(path: &Path, scanner: ScannerConfig) -> Result<()> {
    let mut config = load_config(path)?;
    if config.antispam.antivirus.scanners.iter().any(|s| s.name == scanner.name) {
        return Err(ServerWallError::Config(format!(
            "scanner '{}' already exists",
            scanner.name
        )));
    }
    config.antispam.antivirus.scanners.push(scanner);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Remove an antivirus scanner by name.
pub fn remove_antispam_scanner(path: &Path, name: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.antispam.antivirus.scanners.len();
    config.antispam.antivirus.scanners.retain(|s| s.name != name);
    if config.antispam.antivirus.scanners.len() == before {
        return Err(ServerWallError::Config(format!("scanner '{}' not found", name)));
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Add a trusted host to the relay config.
pub fn add_trusted_host(path: &Path, host: String) -> Result<()> {
    let mut config = load_config(path)?;
    if config.relay.trusted_hosts.hosts.contains(&host) {
        return Err(ServerWallError::Config(format!("trusted host '{}' already exists", host)));
    }
    config.relay.trusted_hosts.hosts.push(host);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Remove a trusted host from the relay config.
pub fn remove_trusted_host(path: &Path, host: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.relay.trusted_hosts.hosts.len();
    config.relay.trusted_hosts.hosts.retain(|h| h != host);
    if config.relay.trusted_hosts.hosts.len() == before {
        return Err(ServerWallError::Config(format!("trusted host '{}' not found", host)));
    }
    validate_config(&config)?;
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
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Update a DMARC policy domain.
pub fn update_dmarc_policy_domain(path: &Path, domain_name: &str, mut domain: DmarcPolicyDomain) -> Result<()> {
    let mut config = load_config(path)?;
    domain.domain = domain_name.to_string();
    let idx = config.relay.dmarc_publish.domains.iter().position(|d| d.domain == domain_name)
        .ok_or_else(|| ServerWallError::Config(format!("DMARC policy for '{}' not found", domain_name)))?;
    config.relay.dmarc_publish.domains[idx] = domain;
    validate_config(&config)?;
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
    validate_config(&config)?;
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
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Update an SPF domain.
pub fn update_spf_domain(path: &Path, domain_name: &str, mut domain: SpfDomainConfig) -> Result<()> {
    let mut config = load_config(path)?;
    domain.domain = domain_name.to_string();
    let idx = config.relay.spf_publish.domains.iter().position(|d| d.domain == domain_name)
        .ok_or_else(|| ServerWallError::Config(format!("SPF record for '{}' not found", domain_name)))?;
    config.relay.spf_publish.domains[idx] = domain;
    validate_config(&config)?;
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
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Replace the relay configuration section entirely.
pub fn set_relay_config(path: &Path, relay: RelayConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.relay = relay;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

// ---------------------------------------------------------------------------
// Security settings
// ---------------------------------------------------------------------------

/// Replace the TLS security sub-section.
pub fn update_security_tls(path: &Path, tls: SecurityTlsConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.tls = tls;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Replace the GeoIP security sub-section.
pub fn update_security_geo(path: &Path, geo: GeoConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.geo = geo;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Replace the security headers sub-section.
pub fn update_security_headers(path: &Path, headers: SecurityHeadersConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.headers = headers;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Replace the bot detection sub-section.
pub fn update_security_bot(path: &Path, bot: BotDetectionConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.bot_detection = bot;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Replace the cookie security sub-section.
pub fn update_security_cookies(path: &Path, cookies: CookieSecurityConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.security.cookies = cookies;
    validate_config(&config)?;
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
    validate_config(&config)?;
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
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn add_security_profile(path: &Path, profile: SecurityProfile) -> Result<()> {
    let mut config = load_config(path)?;
    if config.security_profiles.iter().any(|p| p.name == profile.name) {
        return Err(ServerWallError::Config(format!(
            "Security profile '{}' already exists", profile.name
        )));
    }
    config.security_profiles.push(profile);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn update_security_profile(path: &Path, name: &str, profile: SecurityProfile) -> Result<()> {
    let mut config = load_config(path)?;
    let pos = config.security_profiles.iter().position(|p| p.name == name)
        .ok_or_else(|| ServerWallError::Config(format!("Security profile '{}' not found", name)))?;
    config.security_profiles[pos] = profile;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_security_profile(path: &Path, name: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.security_profiles.len();
    config.security_profiles.retain(|p| p.name != name);
    if config.security_profiles.len() == before {
        return Err(ServerWallError::Config(format!("Security profile '{}' not found", name)));
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn add_tls_profile(path: &Path, profile: TlsProfile) -> Result<()> {
    let mut config = load_config(path)?;
    if config.tls_profiles.iter().any(|p| p.name == profile.name) {
        return Err(ServerWallError::Config(format!(
            "TLS profile '{}' already exists", profile.name
        )));
    }
    config.tls_profiles.push(profile);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn update_tls_profile(path: &Path, name: &str, profile: TlsProfile) -> Result<()> {
    let mut config = load_config(path)?;
    let pos = config.tls_profiles.iter().position(|p| p.name == name)
        .ok_or_else(|| ServerWallError::Config(format!("TLS profile '{}' not found", name)))?;
    config.tls_profiles[pos] = profile;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_tls_profile(path: &Path, name: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.tls_profiles.len();
    config.tls_profiles.retain(|p| p.name != name);
    if config.tls_profiles.len() == before {
        return Err(ServerWallError::Config(format!("TLS profile '{}' not found", name)));
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn add_log_profile(path: &Path, profile: LogProfile) -> Result<()> {
    let mut config = load_config(path)?;
    if config.log_profiles.iter().any(|p| p.name == profile.name) {
        return Err(ServerWallError::Config(format!(
            "Logging profile '{}' already exists", profile.name
        )));
    }
    config.log_profiles.push(profile);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn update_log_profile(path: &Path, name: &str, profile: LogProfile) -> Result<()> {
    let mut config = load_config(path)?;
    let pos = config.log_profiles.iter().position(|p| p.name == name)
        .ok_or_else(|| ServerWallError::Config(format!("Logging profile '{}' not found", name)))?;
    config.log_profiles[pos] = profile;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_log_profile(path: &Path, name: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.log_profiles.len();
    config.log_profiles.retain(|p| p.name != name);
    if config.log_profiles.len() == before {
        return Err(ServerWallError::Config(format!("Logging profile '{}' not found", name)));
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

// ---------------------------------------------------------------------------
// Global and ACME settings
// ---------------------------------------------------------------------------

/// Replace the global daemon settings section.
pub fn update_global_config(path: &Path, global: GlobalConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.global = global;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

/// Replace the ACME / Let's Encrypt settings section.
pub fn update_acme_config(path: &Path, acme: AcmeConfig) -> Result<()> {
    let mut config = load_config(path)?;
    config.acme = acme;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

// ---------------------------------------------------------------------------
// Antispam domain overrides
// ---------------------------------------------------------------------------

pub fn add_antispam_domain_override(path: &Path, entry: DomainOverride) -> Result<()> {
    let mut config = load_config(path)?;
    if config.antispam.domain_overrides.iter().any(|d| d.domain == entry.domain) {
        return Err(ServerWallError::Config(format!(
            "domain override for '{}' already exists", entry.domain
        )));
    }
    config.antispam.domain_overrides.push(entry);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn update_antispam_domain_override(path: &Path, domain: &str, mut entry: DomainOverride) -> Result<()> {
    let mut config = load_config(path)?;
    entry.domain = domain.to_string();
    let idx = config.antispam.domain_overrides.iter().position(|d| d.domain == domain)
        .ok_or_else(|| ServerWallError::Config(format!("domain override for '{}' not found", domain)))?;
    config.antispam.domain_overrides[idx] = entry;
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_antispam_domain_override(path: &Path, domain: &str) -> Result<()> {
    let mut config = load_config(path)?;
    let before = config.antispam.domain_overrides.len();
    config.antispam.domain_overrides.retain(|d| d.domain != domain);
    if config.antispam.domain_overrides.len() == before {
        return Err(ServerWallError::Config(format!("domain override for '{}' not found", domain)));
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

// ---------------------------------------------------------------------------
// Antispam recipient allow/block lists
// ---------------------------------------------------------------------------

pub fn add_antispam_allow_recipient(path: &Path, recipient: &str) -> Result<()> {
    let r = recipient.to_lowercase();
    let mut config = load_config(path)?;
    if !config.antispam.allow.recipients.contains(&r) {
        config.antispam.allow.recipients.push(r);
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_antispam_allow_recipient(path: &Path, recipient: &str) -> Result<()> {
    let r = recipient.to_lowercase();
    let mut config = load_config(path)?;
    config.antispam.allow.recipients.retain(|x| x != &r);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn add_antispam_block_recipient(path: &Path, recipient: &str) -> Result<()> {
    let r = recipient.to_lowercase();
    let mut config = load_config(path)?;
    if !config.antispam.block.recipients.contains(&r) {
        config.antispam.block.recipients.push(r);
    }
    validate_config(&config)?;
    write_config_atomic(path, &config)
}

pub fn remove_antispam_block_recipient(path: &Path, recipient: &str) -> Result<()> {
    let r = recipient.to_lowercase();
    let mut config = load_config(path)?;
    config.antispam.block.recipients.retain(|x| x != &r);
    validate_config(&config)?;
    write_config_atomic(path, &config)
}
