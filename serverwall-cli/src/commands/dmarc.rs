use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::schema::DmarcPolicyDomain;

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct DmarcArgs {
    #[command(subcommand)]
    pub action: DmarcAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum DmarcAction {
    /// List all configured DMARC policy domains.
    List,
    /// Show details of a DMARC policy domain.
    Show {
        /// Domain name.
        domain: String,
    },
    /// Add a DMARC policy for a domain.
    Add {
        /// Domain name (e.g. example.com).
        domain: String,
        /// DMARC policy: none, quarantine, or reject.
        #[arg(long, default_value = "none")]
        policy: String,
        /// Subdomain policy override (none, quarantine, reject, or omit).
        #[arg(long)]
        subdomain_policy: Option<String>,
        /// Percentage of messages to apply policy to (0-100).
        #[arg(long, default_value = "100")]
        pct: u8,
        /// Aggregate report URIs (mailto: addresses, space-separated).
        #[arg(long, value_delimiter = ' ')]
        rua: Vec<String>,
        /// Forensic report URIs (mailto: addresses, space-separated).
        #[arg(long, value_delimiter = ' ')]
        ruf: Vec<String>,
        /// DKIM alignment mode: r (relaxed) or s (strict).
        #[arg(long, default_value = "r")]
        adkim: String,
        /// SPF alignment mode: r (relaxed) or s (strict).
        #[arg(long, default_value = "r")]
        aspf: String,
    },
    /// Update an existing DMARC policy.
    Update {
        /// Domain name to update.
        domain: String,
        /// DMARC policy: none, quarantine, or reject.
        #[arg(long)]
        policy: Option<String>,
        /// Subdomain policy override (or empty to remove).
        #[arg(long)]
        subdomain_policy: Option<String>,
        /// Percentage of messages to apply policy to (0-100).
        #[arg(long)]
        pct: Option<u8>,
        /// Aggregate report URIs (space-separated, replaces existing).
        #[arg(long, value_delimiter = ' ')]
        rua: Option<Vec<String>>,
        /// Forensic report URIs (space-separated, replaces existing).
        #[arg(long, value_delimiter = ' ')]
        ruf: Option<Vec<String>>,
        /// DKIM alignment mode: r or s.
        #[arg(long)]
        adkim: Option<String>,
        /// SPF alignment mode: r or s.
        #[arg(long)]
        aspf: Option<String>,
    },
    /// Remove a DMARC policy domain.
    Remove {
        /// Domain name to remove.
        domain: String,
    },
    /// Show the DNS TXT record value for a DMARC policy domain.
    DnsRecord {
        /// Domain name.
        domain: String,
    },
}

pub fn run(config_path: &Path, args: DmarcArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        DmarcAction::List => {
            let config = load_config(config_path)?;
            let domains = &config.relay.dmarc_publish.domains;
            if args.json {
                println!("{}", serde_json::to_string_pretty(domains)?);
                return Ok(());
            }
            if domains.is_empty() {
                println!("No DMARC policy domains configured.");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = domains.iter().map(|d| vec![
                d.domain.clone(),
                d.policy.clone(),
                d.pct.to_string(),
                d.rua.join(", "),
            ]).collect();
            output::print_table(&["DOMAIN", "POLICY", "PCT", "RUA"], &rows);
        }

        DmarcAction::Show { domain } => {
            let config = load_config(config_path)?;
            let d = config.relay.dmarc_publish.domains.iter().find(|d| d.domain == domain)
                .ok_or_else(|| anyhow::anyhow!("DMARC policy for '{}' not found", domain))?;
            println!("{}", serde_json::to_string_pretty(d)?);
        }

        DmarcAction::Add { domain, policy, subdomain_policy, pct, rua, ruf, adkim, aspf } => {
            let d = DmarcPolicyDomain {
                domain: domain.clone(),
                policy,
                subdomain_policy,
                pct,
                rua,
                ruf,
                adkim,
                aspf,
            };
            editor::add_dmarc_policy_domain(config_path, d)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("DMARC policy for '{}' added.", domain);
            maybe_reload(no_reload);
        }

        DmarcAction::Update { domain, policy, subdomain_policy, pct, rua, ruf, adkim, aspf } => {
            let config = load_config(config_path)?;
            let mut d = config.relay.dmarc_publish.domains.iter()
                .find(|d| d.domain == domain)
                .ok_or_else(|| anyhow::anyhow!("DMARC policy for '{}' not found", domain))?
                .clone();
            if let Some(v) = policy  { d.policy = v; }
            if let Some(v) = pct     { d.pct = v; }
            if let Some(v) = rua     { d.rua = v; }
            if let Some(v) = ruf     { d.ruf = v; }
            if let Some(v) = adkim   { d.adkim = v; }
            if let Some(v) = aspf    { d.aspf = v; }
            d.subdomain_policy = match subdomain_policy {
                Some(ref s) if s.is_empty() => None,
                Some(s) => Some(s),
                None => d.subdomain_policy,
            };
            editor::update_dmarc_policy_domain(config_path, &domain, d)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("DMARC policy for '{}' updated.", domain);
            maybe_reload(no_reload);
        }

        DmarcAction::Remove { domain } => {
            editor::remove_dmarc_policy_domain(config_path, &domain)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("DMARC policy for '{}' removed.", domain);
            maybe_reload(no_reload);
        }

        DmarcAction::DnsRecord { domain } => {
            let config = load_config(config_path)?;
            let d = config.relay.dmarc_publish.domains.iter().find(|d| d.domain == domain)
                .ok_or_else(|| anyhow::anyhow!("DMARC policy for '{}' not found", domain))?;
            let mut parts = vec![
                format!("v=DMARC1"),
                format!("p={}", d.policy),
            ];
            if let Some(ref sp) = d.subdomain_policy { parts.push(format!("sp={}", sp)); }
            if d.pct < 100 { parts.push(format!("pct={}", d.pct)); }
            if !d.rua.is_empty() { parts.push(format!("rua={}", d.rua.join(","))); }
            if !d.ruf.is_empty() { parts.push(format!("ruf={}", d.ruf.join(","))); }
            if d.adkim != "r" { parts.push(format!("adkim={}", d.adkim)); }
            if d.aspf != "r"  { parts.push(format!("aspf={}", d.aspf)); }
            println!("_dmarc.{}  TXT  \"{}\"", domain, parts.join("; "));
        }
    }
    Ok(())
}
