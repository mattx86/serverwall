use std::path::Path;

use crate::config::schema::{FrontendConfig, ServerWallConfig, ProtocolType};
use crate::error::{ServerWallError, Result};

/// Load a ServerWall configuration from a TOML file at the given path.
pub fn load_config(path: &Path) -> Result<ServerWallConfig> {
    let content = std::fs::read_to_string(path).map_err(|e| ServerWallError::ConfigLoad {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut config = load_config_from_str(&content)?;

    // Load conf.d/ drop-in files if configured
    if let Some(ref config_dir) = config.global.config_dir {
        if config_dir.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(config_dir)
                .map_err(|e| ServerWallError::ConfigLoad {
                    path: config_dir.display().to_string(),
                    source: e,
                })?
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "toml")
                        .unwrap_or(false)
                })
                .collect();
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                let fragment_content =
                    std::fs::read_to_string(entry.path()).map_err(|e| ServerWallError::ConfigLoad {
                        path: entry.path().display().to_string(),
                        source: e,
                    })?;
                let fragment: ServerWallConfig = toml::from_str(&fragment_content)
                    .map_err(|e| ServerWallError::Config(format!("{}: {}", entry.path().display(), e)))?;
                merge_config(&mut config, fragment);
            }
        }
    }

    validate_config(&config)?;
    Ok(config)
}

/// Load a ServerWall configuration from a TOML string.
pub fn load_config_from_str(content: &str) -> Result<ServerWallConfig> {
    let config: ServerWallConfig =
        toml::from_str(content).map_err(|e| ServerWallError::Config(e.to_string()))?;
    Ok(config)
}

/// Merge a config fragment into the base config (conf.d/ support).
/// Arrays are appended, scalars from fragment override base only if the fragment
/// has non-default values (we append frontends, backend_pools, waf_rulesets).
fn merge_config(base: &mut ServerWallConfig, fragment: ServerWallConfig) {
    base.frontend.extend(fragment.frontend);
    base.backend_pool.extend(fragment.backend_pool);
    base.waf_ruleset.extend(fragment.waf_ruleset);
    base.antispam.domain_overrides.extend(fragment.antispam.domain_overrides);
    base.relay.dkim.domains.extend(fragment.relay.dkim.domains);
}

/// Validate the loaded configuration for logical consistency.
pub fn validate_config(config: &ServerWallConfig) -> Result<()> {
    let pool_names: Vec<&str> = config.backend_pool.iter().map(|p| p.name.as_str()).collect();

    for frontend in &config.frontend {
        // Every frontend must reference an existing backend pool
        if !pool_names.contains(&frontend.backend_pool.as_str()) {
            return Err(ServerWallError::Config(format!(
                "frontend '{}' references unknown backend_pool '{}'",
                frontend.name, frontend.backend_pool
            )));
        }

        // Frontends with TLS protocols must have TLS configuration
        if requires_tls(frontend) && !has_tls_config(frontend) {
            return Err(ServerWallError::Config(format!(
                "frontend '{}' uses protocol {:?} but has no TLS certificate configured",
                frontend.name, frontend.protocol
            )));
        }

        // Must have at least one listen address
        if frontend.listen.is_empty() {
            return Err(ServerWallError::Config(format!(
                "frontend '{}' has no listen addresses",
                frontend.name
            )));
        }

        // WAF only makes sense for HTTPS
        if frontend.waf_enabled && frontend.protocol != ProtocolType::Https {
            return Err(ServerWallError::Config(format!(
                "frontend '{}' has waf_enabled=true but protocol is {:?} (WAF is HTTPS-only)",
                frontend.name, frontend.protocol
            )));
        }
    }

    // Each backend pool must have at least one backend
    for pool in &config.backend_pool {
        if pool.backend.is_empty() {
            return Err(ServerWallError::Config(format!(
                "backend_pool '{}' has no backends defined",
                pool.name
            )));
        }
    }

    // Check for duplicate frontend names
    let mut frontend_names = std::collections::HashSet::new();
    for f in &config.frontend {
        if !frontend_names.insert(&f.name) {
            return Err(ServerWallError::Config(format!(
                "duplicate frontend name '{}'",
                f.name
            )));
        }
    }

    // Check for duplicate pool names
    let mut pool_name_set = std::collections::HashSet::new();
    for p in &config.backend_pool {
        if !pool_name_set.insert(&p.name) {
            return Err(ServerWallError::Config(format!(
                "duplicate backend_pool name '{}'",
                p.name
            )));
        }
    }

    // Validate antivirus scanner commands have {file} placeholder
    for scanner in &config.antispam.antivirus.scanners {
        if !scanner.command.contains("{file}") {
            return Err(ServerWallError::Config(format!(
                "antivirus scanner '{}' command must contain '{{file}}' placeholder",
                scanner.name
            )));
        }
    }

    // Validate relay trusted hosts are valid CIDRs
    for host in &config.relay.trusted_hosts.hosts {
        host.parse::<ip_network::IpNetwork>()
            .map_err(|_| ServerWallError::Config(format!(
                "relay trusted_host '{}' is not a valid IP or CIDR",
                host
            )))?;
    }

    Ok(())
}

fn requires_tls(frontend: &FrontendConfig) -> bool {
    matches!(
        frontend.protocol,
        ProtocolType::Https | ProtocolType::Smtps | ProtocolType::SmtpStarttls | ProtocolType::Imaps
    )
}

fn has_tls_config(frontend: &FrontendConfig) -> bool {
    frontend.tls_cert.is_some() || frontend.tls_pfx.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_config_parses() {
        let config = load_config_from_str("").unwrap();
        assert!(config.frontend.is_empty());
        assert!(config.backend_pool.is_empty());
    }

    #[test]
    fn test_minimal_valid_config() {
        let toml = r#"
[[frontend]]
name = "web"
protocol = "tcp"
listen = ["0.0.0.0:8080"]
backend_pool = "servers"

[[backend_pool]]
name = "servers"

[[backend_pool.backend]]
name = "srv1"
address = "10.0.0.1:80"
"#;
        let config = load_config_from_str(toml).unwrap();
        assert!(validate_config(&config).is_ok());
        assert_eq!(config.frontend.len(), 1);
        assert_eq!(config.frontend[0].name, "web");
    }

    #[test]
    fn test_missing_backend_pool_fails_validation() {
        let toml = r#"
[[frontend]]
name = "web"
protocol = "tcp"
listen = ["0.0.0.0:8080"]
backend_pool = "nonexistent"
"#;
        let config = load_config_from_str(toml).unwrap();
        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn test_https_without_tls_fails_validation() {
        let toml = r#"
[[frontend]]
name = "web"
protocol = "https"
listen = ["0.0.0.0:443"]
backend_pool = "servers"

[[backend_pool]]
name = "servers"

[[backend_pool.backend]]
name = "srv1"
address = "10.0.0.1:80"
"#;
        let config = load_config_from_str(toml).unwrap();
        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TLS"));
    }

    #[test]
    fn test_waf_on_non_https_fails() {
        let toml = r#"
[[frontend]]
name = "mail"
protocol = "smtps"
listen = ["0.0.0.0:465"]
backend_pool = "mail"
tls_cert = "/etc/serverwall/certs/mail.pem"
tls_key = "/etc/serverwall/certs/mail-key.pem"
waf_enabled = true

[[backend_pool]]
name = "mail"

[[backend_pool.backend]]
name = "mx1"
address = "10.0.0.1:25"
"#;
        let config = load_config_from_str(toml).unwrap();
        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("WAF is HTTPS-only"));
    }

    #[test]
    fn test_duplicate_frontend_names_fails() {
        let toml = r#"
[[frontend]]
name = "web"
protocol = "tcp"
listen = ["0.0.0.0:80"]
backend_pool = "servers"

[[frontend]]
name = "web"
protocol = "tcp"
listen = ["0.0.0.0:81"]
backend_pool = "servers"

[[backend_pool]]
name = "servers"

[[backend_pool.backend]]
name = "srv1"
address = "10.0.0.1:80"
"#;
        let config = load_config_from_str(toml).unwrap();
        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate frontend"));
    }

    #[test]
    fn test_full_config_with_antispam() {
        let toml = r#"
[global]
log_dir = "/var/log/serverwall"

[antispam]
enabled = true
possible_spam_threshold = 40
definite_spam_threshold = 80

[antispam.dnsbl]
enabled = true
weight = 8.0

[[antispam.dnsbl.lists]]
zone = "zen.spamhaus.org"
weight_multiplier = 1.0

[antispam.spf]
enabled = true
weight = 6.0

[antispam.dmarc]
enabled = true
weight = 7.0
honor_reject_policy = true

[[frontend]]
name = "smtp-in"
protocol = "smtps"
listen = ["0.0.0.0:465"]
backend_pool = "mail"
tls_cert = "/etc/serverwall/certs/mail.pem"
tls_key = "/etc/serverwall/certs/mail-key.pem"

[[backend_pool]]
name = "mail"
health_check_type = "smtp"

[[backend_pool.backend]]
name = "mx1"
address = "10.0.0.1:25"

[[backend_pool.backend]]
name = "mx2"
address = "10.0.0.2:25"
"#;
        let config = load_config_from_str(toml).unwrap();
        assert!(validate_config(&config).is_ok());
        assert!(config.antispam.enabled);
        assert_eq!(config.antispam.dnsbl.lists.len(), 1);
        assert_eq!(config.antispam.possible_spam_threshold, 40);
        assert_eq!(config.backend_pool[0].backend.len(), 2);
    }

    #[test]
    fn test_relay_config() {
        let toml = r#"
[relay]
enabled = true
listen = ["0.0.0.0:587"]
hostname = "mail.example.com"

[relay.trusted_hosts]
hosts = ["10.0.0.0/8", "192.168.0.0/16"]

[relay.dkim]
enabled = true

[[relay.dkim.domains]]
domain = "example.com"
selector = "serverwall"
key_file = "/etc/serverwall/dkim/example.com.key"
"#;
        let config = load_config_from_str(toml).unwrap();
        assert!(validate_config(&config).is_ok());
        assert!(config.relay.enabled);
        assert_eq!(config.relay.trusted_hosts.hosts.len(), 2);
        assert_eq!(config.relay.dkim.domains.len(), 1);
    }
}
