use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::schema::DkimDomainConfig;

use crate::output;
use crate::commands::maybe_reload;

#[derive(Args)]
pub struct DkimArgs {
    #[command(subcommand)]
    pub action: DkimAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum DkimAction {
    /// List configured DKIM signing domains.
    List,
    /// Generate a new DKIM key pair for a domain and register it.
    Generate {
        /// Domain to sign (e.g. example.com).
        domain: String,
        /// DKIM selector (e.g. mail, 2024).
        #[arg(long, default_value = "mail")]
        selector: String,
        /// Key directory (default: /opt/serverwall/etc/dkim).
        #[arg(long)]
        key_dir: Option<String>,
    },
    /// Show the DNS TXT record value for a configured domain.
    DnsRecord {
        /// Domain name.
        domain: String,
    },
    /// Remove DKIM signing for a domain.
    Remove {
        /// Domain name.
        domain: String,
    },
}

pub fn run(config_path: &Path, args: DkimArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        DkimAction::List => {
            let config = load_config(config_path)?;
            let domains = &config.relay.dkim.domains;

            if args.json {
                let json: Vec<_> = domains.iter().map(|d| serde_json::json!({
                    "domain": d.domain,
                    "selector": d.selector,
                    "key_file": d.key_file.display().to_string(),
                    "algorithm": d.algorithm,
                })).collect();
                println!("{}", serde_json::to_string_pretty(&json)?);
                return Ok(());
            }

            if domains.is_empty() {
                println!("No DKIM domains configured.");
                return Ok(());
            }

            let rows: Vec<Vec<String>> = domains.iter().map(|d| vec![
                d.domain.clone(),
                d.selector.clone(),
                d.key_file.display().to_string(),
                d.algorithm.clone(),
            ]).collect();
            output::print_table(&["DOMAIN", "SELECTOR", "KEY FILE", "ALGORITHM"], &rows);
        }

        DkimAction::Generate { domain, selector, key_dir } => {
            let key_dir = key_dir
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("/opt/serverwall/etc/dkim"));
            std::fs::create_dir_all(&key_dir)
                .map_err(|e| anyhow::anyhow!("failed to create key dir: {}", e))?;

            let key_file = key_dir.join(format!("{}_{}.pem", domain, selector));

            // Generate RSA 2048-bit private key
            let rsa = openssl::rsa::Rsa::generate(2048)
                .map_err(|e| anyhow::anyhow!("failed to generate RSA key: {}", e))?;
            let pkey = openssl::pkey::PKey::from_rsa(rsa.clone())
                .map_err(|e| anyhow::anyhow!("failed to wrap key: {}", e))?;
            let pem = pkey.private_key_to_pem_pkcs8()
                .map_err(|e| anyhow::anyhow!("failed to encode key: {}", e))?;
            std::fs::write(&key_file, &pem)
                .map_err(|e| anyhow::anyhow!("failed to write key file: {}", e))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| anyhow::anyhow!("failed to chmod key file: {}", e))?;
            }

            // Extract public key DER for DNS record
            let pub_key_der = rsa.public_key_to_der()
                .map_err(|e| anyhow::anyhow!("failed to encode public key: {}", e))?;
            let pub_key_b64 = openssl::base64::encode_block(&pub_key_der);

            let entry = DkimDomainConfig {
                domain: domain.clone(),
                selector: selector.clone(),
                key_file: key_file.clone(),
                algorithm: "rsa-sha256".to_string(),
            };
            editor::add_dkim_domain(config_path, entry)
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("Generated DKIM key: {}", key_file.display());
            println!();
            println!("Add this DNS TXT record:");
            println!("  {}._domainkey.{}  IN TXT  \"v=DKIM1; k=rsa; p={}\"",
                selector, domain, pub_key_b64);
            println!();
            maybe_reload(no_reload);
        }

        DkimAction::DnsRecord { domain } => {
            let config = load_config(config_path)?;
            let entry = config.relay.dkim.domains.iter()
                .find(|d| d.domain == domain)
                .ok_or_else(|| anyhow::anyhow!("no DKIM entry for domain '{}'", domain))?;

            // Read the key file and extract public key
            let pem = std::fs::read(&entry.key_file)
                .map_err(|e| anyhow::anyhow!("failed to read key file {}: {}", entry.key_file.display(), e))?;
            let pkey = openssl::pkey::PKey::private_key_from_pem(&pem)
                .map_err(|e| anyhow::anyhow!("failed to parse key: {}", e))?;
            let rsa = pkey.rsa()
                .map_err(|e| anyhow::anyhow!("key is not RSA: {}", e))?;
            let pub_der = rsa.public_key_to_der()
                .map_err(|e| anyhow::anyhow!("failed to encode public key: {}", e))?;
            let pub_b64 = openssl::base64::encode_block(&pub_der);

            println!("{}._domainkey.{}  IN TXT  \"v=DKIM1; k=rsa; p={}\"",
                entry.selector, domain, pub_b64);
        }

        DkimAction::Remove { domain } => {
            editor::remove_dkim_domain(config_path, &domain)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("DKIM entry for '{}' removed.", domain);
            maybe_reload(no_reload);
        }
    }
    Ok(())
}
