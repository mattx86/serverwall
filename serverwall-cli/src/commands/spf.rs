use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::schema::{SpfDomainConfig, SpfMechanism};

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct SpfArgs {
    #[command(subcommand)]
    pub action: SpfAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum SpfAction {
    /// List all configured SPF domains.
    List,
    /// Show details of an SPF domain configuration.
    Show {
        /// Domain name.
        domain: String,
    },
    /// Add an SPF record for a domain.
    Add {
        /// Domain name (e.g. example.com).
        domain: String,
        /// Mechanisms in the format qualifier:type[:value] e.g. +:mx, +:ip4:1.2.3.0/24, +:include:_spf.example.com
        /// (space-separated, can be repeated).
        #[arg(long, value_delimiter = ' ')]
        mechanisms: Vec<String>,
        /// The ~all / -all / +all / ?all policy (default: -all).
        #[arg(long, default_value = "-all")]
        all: String,
    },
    /// Update an existing SPF domain configuration.
    Update {
        /// Domain name to update.
        domain: String,
        /// Replace mechanisms (space-separated qualifier:type[:value]).
        #[arg(long, value_delimiter = ' ')]
        mechanisms: Option<Vec<String>>,
        /// The ~all / -all / +all / ?all policy.
        #[arg(long)]
        all: Option<String>,
    },
    /// Remove an SPF domain configuration.
    Remove {
        /// Domain name to remove.
        domain: String,
    },
    /// Show the DNS TXT record value for an SPF domain.
    Record {
        /// Domain name.
        domain: String,
    },
}

pub fn run(config_path: &Path, args: SpfArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        SpfAction::List => {
            let config = load_config(config_path)?;
            let domains = &config.relay.spf_publish.domains;
            if args.json {
                println!("{}", serde_json::to_string_pretty(domains)?);
                return Ok(());
            }
            if domains.is_empty() {
                println!("No SPF domains configured.");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = domains.iter().map(|d| vec![
                d.domain.clone(),
                d.mechanisms.len().to_string(),
                d.all.clone(),
            ]).collect();
            output::print_table(&["DOMAIN", "MECHANISMS", "ALL"], &rows);
        }

        SpfAction::Show { domain } => {
            let config = load_config(config_path)?;
            let d = config.relay.spf_publish.domains.iter().find(|d| d.domain == domain)
                .ok_or_else(|| anyhow::anyhow!("SPF record for '{}' not found", domain))?;
            println!("{}", serde_json::to_string_pretty(d)?);
        }

        SpfAction::Add { domain, mechanisms, all } => {
            let parsed = parse_mechanisms(&mechanisms)?;
            let d = SpfDomainConfig { domain: domain.clone(), mechanisms: parsed, all };
            editor::add_spf_domain(config_path, d)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("SPF record for '{}' added.", domain);
            maybe_reload(no_reload);
        }

        SpfAction::Update { domain, mechanisms, all } => {
            let config = load_config(config_path)?;
            let mut d = config.relay.spf_publish.domains.iter()
                .find(|d| d.domain == domain)
                .ok_or_else(|| anyhow::anyhow!("SPF record for '{}' not found", domain))?
                .clone();
            if let Some(mechs) = mechanisms { d.mechanisms = parse_mechanisms(&mechs)?; }
            if let Some(v) = all { d.all = v; }
            editor::update_spf_domain(config_path, &domain, d)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("SPF record for '{}' updated.", domain);
            maybe_reload(no_reload);
        }

        SpfAction::Remove { domain } => {
            editor::remove_spf_domain(config_path, &domain)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("SPF record for '{}' removed.", domain);
            maybe_reload(no_reload);
        }

        SpfAction::Record { domain } => {
            let config = load_config(config_path)?;
            let d = config.relay.spf_publish.domains.iter().find(|d| d.domain == domain)
                .ok_or_else(|| anyhow::anyhow!("SPF record for '{}' not found", domain))?;
            let mut parts = vec!["v=spf1".to_string()];
            for m in &d.mechanisms {
                let q = if m.qualifier == "+" { "".to_string() } else { m.qualifier.clone() };
                match m.value.as_deref() {
                    Some(v) if !v.is_empty() => parts.push(format!("{}{}:{}", q, m.mechanism, v)),
                    _ => parts.push(format!("{}{}", q, m.mechanism)),
                }
            }
            parts.push(d.all.clone());
            println!("{}  TXT  \"{}\"", domain, parts.join(" "));
        }
    }
    Ok(())
}

/// Parse mechanism strings of the form [qualifier:]type[:value] into SpfMechanism structs.
/// Examples: "+mx", "include:_spf.example.com", "-ip4:192.0.2.0/24"
fn parse_mechanisms(items: &[String]) -> anyhow::Result<Vec<SpfMechanism>> {
    let mut result = Vec::new();
    for item in items {
        if item.is_empty() { continue; }
        // Extract qualifier prefix if present
        let (qualifier, rest) = if item.starts_with(['+', '-', '~', '?']) {
            (item[..1].to_string(), &item[1..])
        } else {
            ("+".to_string(), item.as_str())
        };
        // Split on first colon to get mechanism and optional value
        let (mechanism, value) = if let Some(pos) = rest.find(':') {
            (rest[..pos].to_string(), Some(rest[pos+1..].to_string()))
        } else {
            (rest.to_string(), None)
        };
        result.push(SpfMechanism { qualifier, mechanism, value });
    }
    Ok(result)
}
