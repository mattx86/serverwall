use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::schema::{LogFormat, LogProfile};

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct LogProfileArgs {
    #[command(subcommand)]
    pub action: LogProfileAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum LogProfileAction {
    /// List all logging profiles.
    List,
    /// Show details of a logging profile.
    Show {
        /// Profile name.
        name: String,
    },
    /// Add a logging profile.
    Add {
        /// Profile name (unique identifier).
        name: String,
        /// Log format: apache_combined, apache_custom, postfix, protocol, or json.
        #[arg(long, default_value = "apache_combined")]
        format: String,
        /// Disable access logging (enabled by default).
        #[arg(long)]
        no_access_log: bool,
        /// Human-readable description.
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Update an existing logging profile.
    Update {
        /// Profile name to update.
        name: String,
        /// Log format: apache_combined, apache_custom, postfix, protocol, or json.
        #[arg(long)]
        format: Option<String>,
        /// Disable access logging.
        #[arg(long)]
        no_access_log: Option<bool>,
        /// Human-readable description.
        #[arg(long)]
        description: Option<String>,
    },
    /// Remove a logging profile by name.
    Remove {
        /// Profile name to remove.
        name: String,
    },
}

pub fn run(config_path: &Path, args: LogProfileArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        LogProfileAction::List => {
            let config = load_config(config_path)?;
            if args.json {
                let out: Vec<_> = config.log_profiles.iter().map(|p| serde_json::json!({
                    "name": p.name,
                    "format": format!("{:?}", p.format).to_lowercase(),
                    "access_log": p.access_log,
                    "description": p.description,
                })).collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }
            if config.log_profiles.is_empty() {
                println!("No logging profiles configured.");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = config.log_profiles.iter().map(|p| vec![
                p.name.clone(),
                format!("{:?}", p.format).to_lowercase(),
                if p.access_log { "yes".into() } else { "no".into() },
                p.description.clone(),
            ]).collect();
            output::print_table(&["NAME", "FORMAT", "ACCESS LOG", "DESCRIPTION"], &rows);
        }

        LogProfileAction::Show { name } => {
            let config = load_config(config_path)?;
            let p = config.log_profiles.iter().find(|p| p.name == name)
                .ok_or_else(|| anyhow::anyhow!("logging profile '{}' not found", name))?;
            println!("Name:       {}", p.name);
            println!("Format:     {}", format!("{:?}", p.format).to_lowercase());
            println!("Access Log: {}", p.access_log);
            println!("Description:{}", p.description);
        }

        LogProfileAction::Add { name, format, no_access_log, description } => {
            let fmt = parse_log_format(&format)?;
            let profile = LogProfile {
                name: name.clone(),
                description,
                format: fmt,
                access_log: !no_access_log,
            };
            editor::add_log_profile(config_path, profile)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Logging profile '{}' added.", name);
            maybe_reload(no_reload);
        }


        LogProfileAction::Update { name, format, no_access_log, description } => {
            let config = load_config(config_path)?;
            let mut p = config.log_profiles.iter().find(|p| p.name == name)
                .ok_or_else(|| anyhow::anyhow!("logging profile '{}' not found", name))?
                .clone();
            if let Some(f) = format      { p.format = parse_log_format(&f)?; }
            if let Some(v) = no_access_log { p.access_log = !v; }
            if let Some(v) = description { p.description = v; }
            editor::update_log_profile(config_path, &name, p)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Logging profile '{}' updated.", name);
            maybe_reload(no_reload);
        }

        LogProfileAction::Remove { name } => {
            editor::remove_log_profile(config_path, &name)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Logging profile '{}' removed.", name);
            maybe_reload(no_reload);
        }
    }
    Ok(())
}

fn parse_log_format(s: &str) -> anyhow::Result<LogFormat> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "apache_combined" => Ok(LogFormat::ApacheCombined),
        "apache_custom"   => Ok(LogFormat::ApacheCustom),
        "postfix"         => Ok(LogFormat::Postfix),
        "protocol"        => Ok(LogFormat::Protocol),
        "json"            => Ok(LogFormat::Json),
        _ => anyhow::bail!("invalid log format '{}'; use: apache_combined, apache_custom, postfix, protocol, json", s),
    }
}
