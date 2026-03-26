use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};

use crate::commands::maybe_reload;

#[derive(Args)]
pub struct AcmeArgs {
    #[command(subcommand)]
    pub action: AcmeAction,
}

#[derive(Subcommand)]
pub enum AcmeAction {
    /// Show current ACME / Let's Encrypt settings.
    Show,
    /// Update ACME settings (only specified flags are changed).
    Set {
        /// Enable or disable ACME certificate management.
        #[arg(long)]
        enabled: Option<bool>,
        /// Contact email address for Let's Encrypt notifications.
        #[arg(long)]
        email: Option<String>,
        /// ACME directory URL (default: Let's Encrypt production).
        #[arg(long)]
        directory_url: Option<String>,
        /// Challenge type: http01, dns01, or tlsalpn01.
        #[arg(long)]
        challenge_type: Option<String>,
        /// Directory to store ACME state/certificates.
        #[arg(long)]
        storage_dir: Option<String>,
        /// Automatically renew certificates before expiry.
        #[arg(long)]
        auto_renew: Option<bool>,
        /// Days before expiry to trigger renewal (1–90).
        #[arg(long)]
        renew_before_days: Option<u32>,
    },
    /// Add a CIDR to the HTTP-01 challenge server allow list.
    AddCidr {
        /// CIDR range to allow (e.g. 66.133.109.0/24).
        cidr: String,
    },
    /// Remove a CIDR from the HTTP-01 challenge server allow list.
    RemoveCidr {
        /// CIDR range to remove.
        cidr: String,
    },
    /// List CIDRs allowed to reach the HTTP-01 challenge server.
    ListCidrs,
}

pub fn run(config_path: &Path, args: AcmeArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        AcmeAction::Show => {
            let config = load_config(config_path)?;
            let a = &config.acme;
            println!("Enabled:          {}", a.enabled);
            println!("Email:            {}", a.email.as_deref().unwrap_or("(none)"));
            println!("Directory URL:    {}", a.directory_url);
            println!("Challenge Type:   {}", a.challenge_type);
            println!("Storage Dir:      {}", a.storage_dir.display());
            println!("Auto Renew:       {}", a.auto_renew);
            println!("Renew Before:     {} days", a.renew_before_days);
            if a.challenge_allowed_cidrs.is_empty() {
                println!("Challenge CIDRs:  (allow all)");
            } else {
                println!("Challenge CIDRs:  {}", a.challenge_allowed_cidrs.join(", "));
            }
        }

        AcmeAction::Set {
            enabled, email, directory_url, challenge_type,
            storage_dir, auto_renew, renew_before_days,
        } => {
            let config = load_config(config_path)?;
            let mut a = config.acme.clone();
            if let Some(v) = enabled           { a.enabled = v; }
            if let Some(v) = directory_url     { a.directory_url = v; }
            if let Some(v) = challenge_type    { a.challenge_type = v; }
            if let Some(v) = storage_dir       { a.storage_dir = v.into(); }
            if let Some(v) = auto_renew        { a.auto_renew = v; }
            if let Some(v) = renew_before_days { a.renew_before_days = v; }
            // email: Some(Some(v)) = set, Some(None) = clear (not easily expressible via clap Option<Option>)
            // Use Option<String> where empty string means "clear"
            match email {
                Some(ref e) if e.is_empty() => a.email = None,
                Some(e) => a.email = Some(e),
                None => {}
            }
            editor::update_acme_config(config_path, a)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("ACME settings updated.");
            maybe_reload(no_reload);
        }

        AcmeAction::AddCidr { cidr } => {
            let config = load_config(config_path)?;
            let mut a = config.acme.clone();
            if !a.challenge_allowed_cidrs.contains(&cidr) {
                a.challenge_allowed_cidrs.push(cidr.clone());
            } else {
                println!("CIDR '{}' already in list.", cidr);
                return Ok(());
            }
            editor::update_acme_config(config_path, a)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("CIDR '{}' added to challenge allow list.", cidr);
            maybe_reload(no_reload);
        }

        AcmeAction::RemoveCidr { cidr } => {
            let config = load_config(config_path)?;
            let mut a = config.acme.clone();
            let before = a.challenge_allowed_cidrs.len();
            a.challenge_allowed_cidrs.retain(|c| c != &cidr);
            if a.challenge_allowed_cidrs.len() == before {
                anyhow::bail!("CIDR '{}' not found in challenge allow list.", cidr);
            }
            editor::update_acme_config(config_path, a)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("CIDR '{}' removed from challenge allow list.", cidr);
            maybe_reload(no_reload);
        }

        AcmeAction::ListCidrs => {
            let config = load_config(config_path)?;
            if config.acme.challenge_allowed_cidrs.is_empty() {
                println!("Challenge CIDR allow list is empty (all IPs allowed).");
            } else {
                for cidr in &config.acme.challenge_allowed_cidrs {
                    println!("{}", cidr);
                }
            }
        }
    }
    Ok(())
}
