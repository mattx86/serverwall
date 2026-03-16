use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct AclArgs {
    #[command(subcommand)]
    pub action: AclAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum AclAction {
    /// List global IP ACL entries.
    List,
    /// Add an IP to the global allow list.
    Allow {
        /// IP address or CIDR (e.g. 192.168.1.0/24).
        ip: String,
    },
    /// Add an IP to the global block list.
    Block {
        /// IP address or CIDR (e.g. 10.0.0.1).
        ip: String,
    },
    /// Remove an IP from the global ACL (allow or block list).
    Remove {
        /// IP address or CIDR to remove.
        ip: String,
    },
}

pub fn run(config_path: &Path, args: AclArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        AclAction::List => {
            let config = load_config(config_path)?;
            let acl = &config.security.acl.ip;

            if args.json {
                let json = serde_json::json!({
                    "allow": acl.allow,
                    "block": acl.block,
                    "default": format!("{:?}", config.security.acl.default).to_lowercase(),
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
                return Ok(());
            }

            println!("Default action: {}", format!("{:?}", config.security.acl.default).to_lowercase());
            println!();

            if acl.allow.is_empty() && acl.block.is_empty() {
                println!("No global ACL entries configured.");
                return Ok(());
            }

            let mut rows: Vec<Vec<String>> = Vec::new();
            for ip in &acl.allow {
                rows.push(vec![ip.clone(), "allow".to_string()]);
            }
            for ip in &acl.block {
                rows.push(vec![ip.clone(), "block".to_string()]);
            }
            output::print_table(&["IP / CIDR", "ACTION"], &rows);
        }

        AclAction::Allow { ip } => {
            editor::add_acl_allow(config_path, &ip)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Added {} to allow list.", ip);
            maybe_reload(no_reload);
        }

        AclAction::Block { ip } => {
            editor::add_acl_block(config_path, &ip)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Added {} to block list.", ip);
            maybe_reload(no_reload);
        }

        AclAction::Remove { ip } => {
            editor::remove_acl_ip(config_path, &ip)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Removed {} from ACL.", ip);
            maybe_reload(no_reload);
        }
    }
    Ok(())
}
