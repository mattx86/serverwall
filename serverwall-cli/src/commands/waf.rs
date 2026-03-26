use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::schema::WafRulesetConfig;

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct WafArgs {
    #[command(subcommand)]
    pub action: WafAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum WafAction {
    /// List WAF rulesets.
    List,
    /// Show details of a WAF ruleset.
    Show {
        /// Ruleset name.
        name: String,
    },
    /// Add a WAF ruleset.
    Add {
        /// Ruleset name.
        name: String,
        /// WAF mode: blocking, detection_only, or disabled.
        #[arg(long, default_value = "blocking")]
        mode: String,
        /// Path to custom rules directory.
        #[arg(long)]
        rules_dir: Option<String>,
        /// Anomaly score threshold (default: 5).
        #[arg(long, default_value = "5")]
        threshold: u32,
        /// Paranoia level 1-4 (default: 1).
        #[arg(long, default_value = "1")]
        paranoia: u8,
    },
    /// Update an existing WAF ruleset (only specified flags are changed).
    Update {
        /// Ruleset name to update.
        name: String,
        /// WAF mode: blocking, detection_only, or disabled.
        #[arg(long)]
        mode: Option<String>,
        /// Anomaly score threshold.
        #[arg(long)]
        threshold: Option<u32>,
        /// Paranoia level 1-4.
        #[arg(long)]
        paranoia: Option<u8>,
        /// Path to custom rules directory (empty string to clear).
        #[arg(long)]
        rules_dir: Option<String>,
    },
    /// Remove a WAF ruleset by name.
    Remove {
        /// Ruleset name.
        name: String,
    },
}

pub fn run(config_path: &Path, args: WafArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        WafAction::List => {
            let config = load_config(config_path)?;

            if args.json {
                let json: Vec<_> = config.waf_ruleset.iter().map(|r| serde_json::json!({
                    "name": r.name,
                    "mode": format!("{:?}", r.mode).to_lowercase(),
                    "anomaly_threshold": r.anomaly_threshold,
                    "paranoia_level": r.paranoia_level,
                    "rules_dir": r.rules_dir.as_ref().map(|p| p.display().to_string()),
                })).collect();
                println!("{}", serde_json::to_string_pretty(&json)?);
                return Ok(());
            }

            if config.waf_ruleset.is_empty() {
                println!("No WAF rulesets configured.");
                return Ok(());
            }

            let rows: Vec<Vec<String>> = config.waf_ruleset.iter().map(|r| vec![
                r.name.clone(),
                format!("{:?}", r.mode).to_lowercase(),
                r.anomaly_threshold.to_string(),
                r.paranoia_level.to_string(),
                r.rules_dir.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "-".to_string()),
            ]).collect();
            output::print_table(&["NAME", "MODE", "THRESHOLD", "PARANOIA", "RULES DIR"], &rows);
        }

        WafAction::Show { name } => {
            let config = load_config(config_path)?;
            let r = config.waf_ruleset.iter().find(|r| r.name == name)
                .ok_or_else(|| anyhow::anyhow!("WAF ruleset '{}' not found", name))?;
            println!("Name:      {}", r.name);
            println!("Mode:      {}", format!("{:?}", r.mode).to_lowercase());
            println!("Threshold: {}", r.anomaly_threshold);
            println!("Paranoia:  {}", r.paranoia_level);
            if let Some(ref d) = r.rules_dir {
                println!("Rules Dir: {}", d.display());
            }
            if !r.exclusions.paths.is_empty() {
                println!("Excl Paths: {}", r.exclusions.paths.join(", "));
            }
            if !r.exclusions.ip_addresses.is_empty() {
                println!("Excl IPs:   {}", r.exclusions.ip_addresses.join(", "));
            }
        }

        WafAction::Add { name, mode, rules_dir, threshold, paranoia } => {
            let waf_mode = parse_waf_mode(&mode)?;
            let ruleset = WafRulesetConfig {
                name: name.clone(),
                mode: waf_mode,
                anomaly_threshold: threshold,
                rules_dir: rules_dir.map(std::path::PathBuf::from),
                paranoia_level: paranoia,
                exclusions: Default::default(),
                custom_rules: Vec::new(),
            };
            editor::add_waf_ruleset(config_path, ruleset)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("WAF ruleset '{}' added.", name);
            maybe_reload(no_reload);
        }

        WafAction::Update { name, mode, rules_dir, threshold, paranoia } => {
            let config = load_config(config_path)?;
            let mut ruleset = config.waf_ruleset.iter().find(|r| r.name == name)
                .ok_or_else(|| anyhow::anyhow!("WAF ruleset '{}' not found", name))?
                .clone();
            if let Some(v) = mode      { ruleset.mode = parse_waf_mode(&v)?; }
            if let Some(v) = threshold { ruleset.anomaly_threshold = v; }
            if let Some(v) = paranoia  { ruleset.paranoia_level = v; }
            ruleset.rules_dir = match rules_dir {
                Some(ref s) if s.is_empty() => None,
                Some(s) => Some(std::path::PathBuf::from(s)),
                None => ruleset.rules_dir,
            };
            editor::update_waf_ruleset(config_path, &name, ruleset)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("WAF ruleset '{}' updated.", name);
            maybe_reload(no_reload);
        }

        WafAction::Remove { name } => {
            editor::remove_waf_ruleset(config_path, &name)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("WAF ruleset '{}' removed.", name);
            maybe_reload(no_reload);
        }
    }
    Ok(())
}

fn parse_waf_mode(s: &str) -> anyhow::Result<serverwall_core::config::schema::WafMode> {
    use serverwall_core::config::schema::WafMode;
    match s.to_lowercase().as_str() {
        "blocking" => Ok(WafMode::Blocking),
        "detection_only" | "detection-only" => Ok(WafMode::DetectionOnly),
        "disabled" => Ok(WafMode::Disabled),
        _ => anyhow::bail!("invalid WAF mode '{}'; use: blocking, detection_only, disabled", s),
    }
}
