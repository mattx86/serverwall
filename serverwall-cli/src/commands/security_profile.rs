use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::schema::SecurityProfile;

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct SecurityProfileArgs {
    #[command(subcommand)]
    pub action: SecurityProfileAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum SecurityProfileAction {
    /// List all security profiles.
    List,
    /// Show details of a security profile.
    Show {
        /// Profile name.
        name: String,
    },
    /// Add a security profile from a JSON file.
    Add {
        /// Path to a JSON file containing the full security profile definition.
        #[arg(long)]
        from_json: String,
    },
    /// Replace a security profile with a new definition from a JSON file.
    Update {
        /// Profile name to update.
        name: String,
        /// Path to a JSON file containing the updated security profile definition.
        #[arg(long)]
        from_json: String,
    },
    /// Remove a security profile by name.
    Remove {
        /// Profile name to remove.
        name: String,
    },
}

pub fn run(config_path: &Path, args: SecurityProfileArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        SecurityProfileAction::List => {
            let config = load_config(config_path)?;
            if args.json {
                let out: Vec<_> = config.security_profiles.iter().map(|p| serde_json::json!({
                    "name": p.name,
                    "description": p.description,
                    "profile_type": p.profile_type,
                    "waf_enabled": p.waf_enabled,
                })).collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }
            if config.security_profiles.is_empty() {
                println!("No security profiles configured.");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = config.security_profiles.iter().map(|p| vec![
                p.name.clone(),
                p.profile_type.clone(),
                p.description.clone(),
                if p.waf_enabled { "yes".into() } else { "no".into() },
            ]).collect();
            output::print_table(&["NAME", "TYPE", "DESCRIPTION", "WAF"], &rows);
        }

        SecurityProfileAction::Show { name } => {
            let config = load_config(config_path)?;
            let p = config.security_profiles.iter().find(|p| p.name == name)
                .ok_or_else(|| anyhow::anyhow!("security profile '{}' not found", name))?;
            let json = serde_json::to_string_pretty(p)?;
            println!("{}", json);
        }

        SecurityProfileAction::Add { from_json } => {
            let content = std::fs::read_to_string(&from_json)
                .map_err(|e| anyhow::anyhow!("failed to read '{}': {}", from_json, e))?;
            let profile: SecurityProfile = serde_json::from_str(&content)
                .map_err(|e| anyhow::anyhow!("invalid JSON: {}", e))?;
            let name = profile.name.clone();
            editor::add_security_profile(config_path, profile)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Security profile '{}' added.", name);
            maybe_reload(no_reload);
        }

        SecurityProfileAction::Update { name, from_json } => {
            let content = std::fs::read_to_string(&from_json)
                .map_err(|e| anyhow::anyhow!("failed to read '{}': {}", from_json, e))?;
            let mut profile: SecurityProfile = serde_json::from_str(&content)
                .map_err(|e| anyhow::anyhow!("invalid JSON: {}", e))?;
            profile.name = name.clone();
            editor::update_security_profile(config_path, &name, profile)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Security profile '{}' updated.", name);
            maybe_reload(no_reload);
        }

        SecurityProfileAction::Remove { name } => {
            editor::remove_security_profile(config_path, &name)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Security profile '{}' removed.", name);
            maybe_reload(no_reload);
        }
    }
    Ok(())
}
