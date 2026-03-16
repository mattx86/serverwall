use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};

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
    /// Remove a backend pool by name.
    RemovePool {
        /// Pool name to remove.
        name: String,
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
            println!("Pool:         {}", pool.name);
            println!("Health Check: {}", format!("{:?}", pool.health_check_type).to_lowercase());
            println!("Interval:     {}", pool.health_check_interval);
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

        BackendAction::RemovePool { name } => {
            editor::remove_backend_pool(config_path, &name)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Backend pool '{}' removed.", name);
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
