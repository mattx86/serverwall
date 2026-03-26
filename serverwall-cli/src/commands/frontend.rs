use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::schema::{BalanceMethod, FrontendConfig, ProtocolType};

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct FrontendArgs {
    #[command(subcommand)]
    pub action: FrontendAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum FrontendAction {
    /// List all frontends.
    List,
    /// Show details of a specific frontend.
    Show {
        /// Frontend name.
        name: String,
    },
    /// Add a new frontend.
    Add {
        /// Frontend name (unique identifier).
        name: String,
        /// Protocol: https, smtps, smtp-starttls, imaps, tcp, or stratum.
        #[arg(long)]
        protocol: String,
        /// Listen addresses (comma-separated, e.g. 0.0.0.0:443,0.0.0.0:8443).
        #[arg(long, value_delimiter = ',', required = true)]
        listen: Vec<String>,
        /// Backend pool name.
        #[arg(long)]
        backend_pool: String,
        /// Load balancer algorithm: round_robin, least_connections, ip_hash, sticky_session.
        #[arg(long, default_value = "round_robin")]
        balancer: String,
        /// Path to TLS certificate file (PEM).
        #[arg(long)]
        tls_cert: Option<String>,
        /// Path to TLS key file (PEM).
        #[arg(long)]
        tls_key: Option<String>,
        /// Path to TLS chain file (PEM, optional separate chain).
        #[arg(long)]
        tls_chain: Option<String>,
        /// Password for encrypted TLS key file.
        #[arg(long)]
        tls_key_password: Option<String>,
        /// Path to PKCS#12/PFX certificate file.
        #[arg(long)]
        tls_pfx: Option<String>,
        /// Password for PKCS#12/PFX certificate file.
        #[arg(long)]
        tls_pfx_password: Option<String>,
        /// Enable WAF for this frontend.
        #[arg(long)]
        waf_enabled: bool,
        /// WAF ruleset name to apply.
        #[arg(long)]
        waf_ruleset: Option<String>,
        /// Security profile name to apply.
        #[arg(long)]
        security_profile: Option<String>,
        /// Log profile name to apply.
        #[arg(long)]
        log_profile: Option<String>,
        /// Maximum simultaneous connections (0 = unlimited).
        #[arg(long)]
        max_connections: Option<usize>,
        /// Load a full configuration from a JSON file (overrides all other flags).
        #[arg(long)]
        from_json: Option<String>,
    },
    /// Update an existing frontend (only specified flags are changed).
    Update {
        /// Frontend name to update.
        name: String,
        /// Protocol: https, smtps, smtp-starttls, imaps, tcp, or stratum.
        #[arg(long)]
        protocol: Option<String>,
        /// Listen addresses (comma-separated, replaces existing).
        #[arg(long, value_delimiter = ',')]
        listen: Option<Vec<String>>,
        /// Backend pool name.
        #[arg(long)]
        backend_pool: Option<String>,
        /// Load balancer algorithm.
        #[arg(long)]
        balancer: Option<String>,
        /// Path to TLS certificate file.
        #[arg(long)]
        tls_cert: Option<String>,
        /// Path to TLS key file.
        #[arg(long)]
        tls_key: Option<String>,
        /// Path to TLS chain file (PEM, optional separate chain).
        #[arg(long)]
        tls_chain: Option<String>,
        /// Password for encrypted TLS key file.
        #[arg(long)]
        tls_key_password: Option<String>,
        /// Path to PKCS#12/PFX certificate file.
        #[arg(long)]
        tls_pfx: Option<String>,
        /// Password for PKCS#12/PFX certificate file.
        #[arg(long)]
        tls_pfx_password: Option<String>,
        /// Enable or disable WAF for this frontend.
        #[arg(long)]
        waf_enabled: Option<bool>,
        /// WAF ruleset name (or empty to clear).
        #[arg(long)]
        waf_ruleset: Option<String>,
        /// Security profile name (or empty to clear).
        #[arg(long)]
        security_profile: Option<String>,
        /// Log profile name (or empty to clear).
        #[arg(long)]
        log_profile: Option<String>,
        /// Maximum simultaneous connections (0 = unlimited).
        #[arg(long)]
        max_connections: Option<usize>,
        /// Replace the entire frontend configuration from a JSON file.
        #[arg(long)]
        from_json: Option<String>,
    },
    /// Remove a frontend by name.
    Remove {
        /// Frontend name to remove.
        name: String,
    },
}

pub fn run(config_path: &Path, args: FrontendArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        FrontendAction::List => {
            let config = load_config(config_path)?;
            if args.json {
                let frontends: Vec<_> = config.frontend.iter().map(|f| serde_json::json!({
                    "name": f.name,
                    "protocol": format!("{:?}", f.protocol).to_lowercase(),
                    "listen": f.listen,
                    "backend_pool": f.backend_pool,
                    "balancer": format!("{:?}", f.balancer).to_lowercase(),
                    "waf_enabled": f.waf_enabled,
                })).collect();
                println!("{}", serde_json::to_string_pretty(&frontends)?);
                return Ok(());
            }
            let rows: Vec<Vec<String>> = config.frontend.iter().map(|f| vec![
                f.name.clone(),
                format!("{:?}", f.protocol).to_lowercase(),
                f.listen.join(", "),
                f.backend_pool.clone(),
                format!("{:?}", f.balancer).to_lowercase(),
            ]).collect();
            output::print_table(&["NAME", "PROTOCOL", "LISTEN", "BACKEND POOL", "BALANCER"], &rows);
        }

        FrontendAction::Show { name } => {
            let config = load_config(config_path)?;
            let f = config.frontend.iter().find(|f| f.name == name)
                .ok_or_else(|| anyhow::anyhow!("frontend '{}' not found", name))?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(f)?);
                return Ok(());
            }
            println!("Frontend: {}", f.name);
            println!("Protocol: {}", format!("{:?}", f.protocol).to_lowercase());
            println!("Listen:   {}", f.listen.join(", "));
            println!("Pool:     {}", f.backend_pool);
            println!("Balancer: {}", format!("{:?}", f.balancer).to_lowercase());
            println!("WAF:      {}", f.waf_enabled);
            if let Some(ref waf) = f.waf_ruleset {
                println!("WAF Set:  {}", waf);
            }
            if let Some(ref sp) = f.security_profile {
                println!("Sec Prof: {}", sp);
            }
            if let Some(ref lp) = f.log_profile {
                println!("Log Prof: {}", lp);
            }
        }

        FrontendAction::Add {
            name, protocol, listen, backend_pool, balancer,
            tls_cert, tls_key, tls_chain, tls_key_password, tls_pfx, tls_pfx_password,
            waf_enabled, waf_ruleset, security_profile, log_profile,
            max_connections, from_json,
        } => {
            let frontend = if let Some(ref path) = from_json {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("failed to read '{}': {}", path, e))?;
                let mut f: FrontendConfig = serde_json::from_str(&content)
                    .map_err(|e| anyhow::anyhow!("invalid JSON: {}", e))?;
                f.name = name.clone();
                f
            } else {
                let proto = parse_protocol(&protocol)?;
                let bal = parse_balancer(&balancer)?;
                FrontendConfig {
                    name: name.clone(),
                    protocol: proto,
                    listen,
                    backend_pool,
                    tls_cert: tls_cert.map(Into::into),
                    tls_key: tls_key.map(Into::into),
                    tls_chain: tls_chain.map(Into::into),
                    tls_key_password,
                    tls_pfx: tls_pfx.map(Into::into),
                    tls_pfx_password,
                    waf_enabled,
                    waf_ruleset,
                    security_profile,
                    log_profile,
                    balancer: bal,
                    max_connections,
                    ..frontend_defaults(name.clone())
                }
            };
            editor::add_frontend(config_path, frontend)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Frontend '{}' added.", name);
            maybe_reload(no_reload);
        }

        FrontendAction::Update {
            name, protocol, listen, backend_pool, balancer,
            tls_cert, tls_key, tls_chain, tls_key_password, tls_pfx, tls_pfx_password,
            waf_enabled, waf_ruleset, security_profile, log_profile, max_connections, from_json,
        } => {
            let frontend = if let Some(ref path) = from_json {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("failed to read '{}': {}", path, e))?;
                let mut f: FrontendConfig = serde_json::from_str(&content)
                    .map_err(|e| anyhow::anyhow!("invalid JSON: {}", e))?;
                f.name = name.clone();
                f
            } else {
                let config = load_config(config_path)?;
                let mut f = config.frontend.iter().find(|f| f.name == name)
                    .ok_or_else(|| anyhow::anyhow!("frontend '{}' not found", name))?
                    .clone();
                if let Some(v) = protocol     { f.protocol = parse_protocol(&v)?; }
                if let Some(v) = listen       { f.listen = v; }
                if let Some(v) = backend_pool { f.backend_pool = v; }
                if let Some(v) = balancer     { f.balancer = parse_balancer(&v)?; }
                if let Some(v) = waf_enabled  { f.waf_enabled = v; }
                if let Some(v) = max_connections { f.max_connections = Some(v); }
                if let Some(v) = tls_cert          { f.tls_cert         = if v.is_empty() { None } else { Some(v.into()) }; }
                if let Some(v) = tls_key           { f.tls_key          = if v.is_empty() { None } else { Some(v.into()) }; }
                if let Some(v) = tls_key_password  { f.tls_key_password = if v.is_empty() { None } else { Some(v) }; }
                if let Some(v) = tls_pfx_password  { f.tls_pfx_password = if v.is_empty() { None } else { Some(v) }; }
                f.tls_chain = match tls_chain {
                    Some(ref s) if s.is_empty() => None,
                    Some(s) => Some(s.into()),
                    None => f.tls_chain,
                };
                f.tls_pfx = match tls_pfx {
                    Some(ref s) if s.is_empty() => None,
                    Some(s) => Some(s.into()),
                    None => f.tls_pfx,
                };
                f.waf_ruleset = match waf_ruleset {
                    Some(ref s) if s.is_empty() => None,
                    Some(s) => Some(s),
                    None => f.waf_ruleset,
                };
                f.security_profile = match security_profile {
                    Some(ref s) if s.is_empty() => None,
                    Some(s) => Some(s),
                    None => f.security_profile,
                };
                f.log_profile = match log_profile {
                    Some(ref s) if s.is_empty() => None,
                    Some(s) => Some(s),
                    None => f.log_profile,
                };
                f
            };
            editor::update_frontend(config_path, &name, frontend)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Frontend '{}' updated.", name);
            maybe_reload(no_reload);
        }

        FrontendAction::Remove { name } => {
            editor::remove_frontend(config_path, &name)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Frontend '{}' removed.", name);
            maybe_reload(no_reload);
        }
    }
    Ok(())
}

fn parse_protocol(s: &str) -> anyhow::Result<ProtocolType> {
    match s.to_lowercase().replace('_', "-").as_str() {
        "https"          => Ok(ProtocolType::Https),
        "smtps"          => Ok(ProtocolType::Smtps),
        "smtp-starttls"  => Ok(ProtocolType::SmtpStarttls),
        "imaps"          => Ok(ProtocolType::Imaps),
        "tcp"            => Ok(ProtocolType::Tcp),
        "stratum"        => Ok(ProtocolType::Stratum),
        _ => anyhow::bail!("invalid protocol '{}'; use: https, smtps, smtp-starttls, imaps, tcp, stratum", s),
    }
}

fn parse_balancer(s: &str) -> anyhow::Result<BalanceMethod> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "round_robin"        => Ok(BalanceMethod::RoundRobin),
        "least_connections"  => Ok(BalanceMethod::LeastConnections),
        "ip_hash"            => Ok(BalanceMethod::IpHash),
        "sticky_session"     => Ok(BalanceMethod::StickySession),
        _ => anyhow::bail!("invalid balancer '{}'; use: round_robin, least_connections, ip_hash, sticky_session", s),
    }
}

fn frontend_defaults(name: String) -> FrontendConfig {
    use serverwall_core::config::schema::{
        FrontendAclConfig, FrontendHeadersConfig, LogFormat, SmtpHeadersConfig,
    };
    FrontendConfig {
        name,
        protocol: ProtocolType::Https,
        listen: Vec::new(),
        backend_pool: String::new(),
        tls_cert: None,
        tls_chain: None,
        tls_key: None,
        tls_key_password: None,
        tls_pfx: None,
        tls_pfx_password: None,
        tls_min_version: "1.2".into(),
        tls_ciphers: Vec::new(),
        balancer: BalanceMethod::RoundRobin,
        waf_enabled: false,
        waf_ruleset: None,
        security_profile: None,
        log_file: None,
        log_format: LogFormat::ApacheCombined,
        access_log: true,
        log_profile: None,
        headers: FrontendHeadersConfig::default(),
        smtp_headers: SmtpHeadersConfig::default(),
        acl: FrontendAclConfig::default(),
        max_connections: None,
        session_cookie: "_s".into(),
    }
}
