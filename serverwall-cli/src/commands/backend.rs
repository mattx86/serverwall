use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::schema::{BackendConfig, BackendPoolConfig, HealthCheckType};

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct BackendArgs {
    #[command(subcommand)]
    pub action: BackendAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum BackendAction {
    /// List all backend pools and their servers.
    List,
    /// Show details of a backend pool.
    Show {
        /// Pool name.
        name: String,
    },
    /// Add a new backend pool.
    AddPool {
        /// Pool name (unique identifier).
        name: String,
        /// Health check type: tcp, http, smtp, imap, or stratum.
        #[arg(long, default_value = "tcp")]
        health_check_type: String,
        /// Health check interval (e.g. 10s).
        #[arg(long, default_value = "10s")]
        health_check_interval: String,
        /// Health check timeout (e.g. 3s).
        #[arg(long, default_value = "3s")]
        health_check_timeout: String,
        /// HTTP health check path (e.g. /health).
        #[arg(long)]
        health_check_path: Option<String>,
        /// Expected HTTP status code for successful health check.
        #[arg(long, default_value = "200")]
        health_check_expect: u16,
        /// Use TLS for health checks.
        #[arg(long)]
        health_check_tls: bool,
        /// Skip certificate verification in health checks.
        #[arg(long)]
        health_check_ignore_cert: bool,
        /// HTTP method to use for health checks (GET or POST).
        #[arg(long, default_value = "GET")]
        health_check_method: String,
    },
    /// Update an existing backend pool's health check settings.
    UpdatePool {
        /// Pool name to update.
        name: String,
        /// Health check type: tcp, http, smtp, imap, or stratum.
        #[arg(long)]
        health_check_type: Option<String>,
        /// Health check interval (e.g. 10s).
        #[arg(long)]
        health_check_interval: Option<String>,
        /// Health check timeout (e.g. 3s).
        #[arg(long)]
        health_check_timeout: Option<String>,
        /// HTTP health check path (or empty to clear).
        #[arg(long)]
        health_check_path: Option<String>,
        /// Expected HTTP status code.
        #[arg(long)]
        health_check_expect: Option<u16>,
        /// Use TLS for health checks.
        #[arg(long)]
        health_check_tls: Option<bool>,
        /// Skip certificate verification in health checks.
        #[arg(long)]
        health_check_ignore_cert: Option<bool>,
        /// HTTP method to use for health checks (GET or POST).
        #[arg(long)]
        health_check_method: Option<String>,
    },
    /// Remove a backend pool by name.
    RemovePool {
        /// Pool name to remove.
        name: String,
    },
    /// Add a backend server to a pool.
    AddServer {
        /// Pool name.
        pool: String,
        /// Backend server address (host:port).
        address: String,
        /// Backend server name (defaults to address).
        #[arg(long)]
        name: Option<String>,
        /// Load balancing weight (default: 1).
        #[arg(long, default_value = "1")]
        weight: u32,
        /// Use TLS to connect to this backend.
        #[arg(long)]
        tls: bool,
        /// Verify backend TLS certificate.
        #[arg(long)]
        tls_verify: Option<bool>,
        /// SNI hostname to send when connecting to backend via TLS.
        #[arg(long)]
        tls_sni: Option<String>,
        /// Maximum connections to this backend (0 = unlimited).
        #[arg(long)]
        max_connections: Option<usize>,
        /// Start the backend as disabled.
        #[arg(long)]
        disable: bool,
    },
    /// Remove a backend server from a pool.
    RemoveBackend {
        /// Pool name.
        pool: String,
        /// Backend name.
        name: String,
    },
}

pub fn run(config_path: &Path, args: BackendArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        BackendAction::List => {
            let config = load_config(config_path)?;
            if args.json {
                let pools: Vec<_> = config.backend_pool.iter().map(|p| serde_json::json!({
                    "name": p.name,
                    "health_check_type": format!("{:?}", p.health_check_type).to_lowercase(),
                    "backends": p.backend.iter().map(|b| serde_json::json!({
                        "name": b.name,
                        "address": b.address,
                        "weight": b.weight,
                        "tls": b.tls,
                        "enabled": b.enabled,
                    })).collect::<Vec<_>>(),
                })).collect();
                println!("{}", serde_json::to_string_pretty(&pools)?);
                return Ok(());
            }
            let mut rows: Vec<Vec<String>> = Vec::new();
            for pool in &config.backend_pool {
                for b in &pool.backend {
                    rows.push(vec![
                        pool.name.clone(),
                        b.name.clone(),
                        b.address.clone(),
                        b.weight.to_string(),
                        if b.enabled { "enabled".into() } else { "disabled".into() },
                    ]);
                }
            }
            output::print_table(&["POOL", "BACKEND", "ADDRESS", "WEIGHT", "STATUS"], &rows);
        }

        BackendAction::Show { name } => {
            let config = load_config(config_path)?;
            let pool = config.backend_pool.iter().find(|p| p.name == name)
                .ok_or_else(|| anyhow::anyhow!("backend pool '{}' not found", name))?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(pool)?);
                return Ok(());
            }
            println!("Pool:         {}", pool.name);
            println!("Health Check: {}", format!("{:?}", pool.health_check_type).to_lowercase());
            println!("Interval:     {}", pool.health_check_interval);
            println!("Timeout:      {}", pool.health_check_timeout);
            if let Some(ref p) = pool.health_check_path {
                println!("HC Path:      {}", p);
            }
            println!("HC Expect:    {}", pool.health_check_expect);
            println!("HC TLS:       {}", pool.health_check_tls);
            if !pool.backend.is_empty() {
                println!("\nBackends:");
                let rows: Vec<Vec<String>> = pool.backend.iter().map(|b| vec![
                    b.name.clone(),
                    b.address.clone(),
                    b.weight.to_string(),
                    if b.enabled { "enabled".into() } else { "disabled".into() },
                ]).collect();
                output::print_table(&["NAME", "ADDRESS", "WEIGHT", "STATUS"], &rows);
            }
        }

        BackendAction::AddPool {
            name, health_check_type, health_check_interval, health_check_timeout,
            health_check_path, health_check_expect, health_check_tls, health_check_ignore_cert,
            health_check_method,
        } => {
            let pool = BackendPoolConfig {
                name: name.clone(),
                health_check_type: parse_health_check_type(&health_check_type)?,
                health_check_interval,
                health_check_timeout,
                health_check_path,
                health_check_expect,
                health_check_tls,
                health_check_ignore_cert,
                health_check_method,
                backend: Vec::new(),
            };
            editor::add_backend_pool(config_path, pool)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Backend pool '{}' added.", name);
            maybe_reload(no_reload);
        }

        BackendAction::UpdatePool {
            name, health_check_type, health_check_interval, health_check_timeout,
            health_check_path, health_check_expect, health_check_tls, health_check_ignore_cert,
            health_check_method,
        } => {
            let config = load_config(config_path)?;
            let mut pool = config.backend_pool.iter().find(|p| p.name == name)
                .ok_or_else(|| anyhow::anyhow!("backend pool '{}' not found", name))?
                .clone();
            if let Some(v) = health_check_type     { pool.health_check_type = parse_health_check_type(&v)?; }
            if let Some(v) = health_check_interval { pool.health_check_interval = v; }
            if let Some(v) = health_check_timeout  { pool.health_check_timeout = v; }
            if let Some(v) = health_check_expect   { pool.health_check_expect = v; }
            if let Some(v) = health_check_tls      { pool.health_check_tls = v; }
            if let Some(v) = health_check_ignore_cert { pool.health_check_ignore_cert = v; }
            if let Some(v) = health_check_method   { pool.health_check_method = v; }
            pool.health_check_path = match health_check_path {
                Some(ref s) if s.is_empty() => None,
                Some(s) => Some(s),
                None => pool.health_check_path,
            };
            editor::update_backend_pool(config_path, &name, pool)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Backend pool '{}' updated.", name);
            maybe_reload(no_reload);
        }

        BackendAction::RemovePool { name } => {
            editor::remove_backend_pool(config_path, &name)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Backend pool '{}' removed.", name);
            maybe_reload(no_reload);
        }

        BackendAction::AddServer { pool, address, name, weight, tls, tls_verify, tls_sni, max_connections, disable } => {
            let backend_name = name.unwrap_or_else(|| address.clone());
            let backend = BackendConfig {
                name: backend_name.clone(),
                address: address.clone(),
                weight,
                tls,
                tls_verify,
                tls_sni,
                max_connections,
                enabled: !disable,
            };
            editor::add_backend(config_path, &pool, backend)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Backend '{}' added to pool '{}'.", backend_name, pool);
            maybe_reload(no_reload);
        }

        BackendAction::RemoveBackend { pool, name } => {
            editor::remove_backend(config_path, &pool, &name)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Backend '{}' removed from pool '{}'.", name, pool);
            maybe_reload(no_reload);
        }
    }
    Ok(())
}

fn parse_health_check_type(s: &str) -> anyhow::Result<HealthCheckType> {
    match s.to_lowercase().as_str() {
        "tcp"     => Ok(HealthCheckType::Tcp),
        "http"    => Ok(HealthCheckType::Http),
        "smtp"    => Ok(HealthCheckType::Smtp),
        "imap"    => Ok(HealthCheckType::Imap),
        "stratum" => Ok(HealthCheckType::Stratum),
        _ => anyhow::bail!("invalid health check type '{}'; use: tcp, http, smtp, imap, stratum", s),
    }
}
