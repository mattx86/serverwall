use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};

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
            println!("Frontend: {}", f.name);
            println!("Protocol: {}", format!("{:?}", f.protocol).to_lowercase());
            println!("Listen:   {}", f.listen.join(", "));
            println!("Pool:     {}", f.backend_pool);
            println!("Balancer: {}", format!("{:?}", f.balancer).to_lowercase());
            println!("WAF:      {}", f.waf_enabled);
            if let Some(ref waf) = f.waf_ruleset {
                println!("WAF Set:  {}", waf);
            }
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
