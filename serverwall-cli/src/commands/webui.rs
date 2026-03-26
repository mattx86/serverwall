use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

use serverwall_core::acl::IpMatcher;
use serverwall_core::config::{editor, load_config};
use serverwall_core::{send_reload_signal, DEFAULT_WEBUI_PID_FILE};

use crate::output;

#[derive(Args)]
pub struct WebuiArgs {
    #[command(subcommand)]
    pub action: WebuiAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum WebuiAction {
    /// Show all WebUI configuration settings.
    Show,
    /// Update WebUI connection settings (only specified flags are changed).
    /// Note: changes to listen address and TLS cert/key require restarting the WebUI service.
    SetConfig {
        /// Enable or disable the WebUI service.
        #[arg(long)]
        enabled: Option<bool>,
        /// Listen address for the WebUI (e.g. 0.0.0.0:8443).
        #[arg(long)]
        listen: Option<String>,
        /// Path to the TLS certificate file for the WebUI.
        #[arg(long)]
        tls_cert: Option<String>,
        /// Path to the TLS key file for the WebUI.
        #[arg(long)]
        tls_key: Option<String>,
        /// Path to the API bearer tokens file.
        #[arg(long)]
        tokens_file: Option<String>,
        /// Path to the web UI users file.
        #[arg(long)]
        web_users_file: Option<String>,
    },
    /// Add an allowed CORS origin for the WebUI.
    AddOrigin {
        /// Origin URL to allow (e.g. https://admin.example.com).
        origin: String,
    },
    /// Remove a CORS origin from the WebUI allow list.
    RemoveOrigin {
        /// Origin URL to remove.
        origin: String,
    },
    /// List allowed CORS origins.
    ListOrigins,
    // ---- IP allowlist (existing commands) ----
    /// List the current WebUI IP allowlist.
    List,
    /// Add a CIDR to the WebUI IP allowlist.
    Add {
        /// IP address or CIDR to add (e.g. 10.0.0.0/8).
        cidr: String,
    },
    /// Remove a CIDR from the WebUI IP allowlist.
    Remove {
        /// IP address or CIDR to remove.
        cidr: String,
    },
    /// Replace the entire WebUI IP allowlist.
    Set {
        /// One or more CIDRs (e.g. 10.0.0.0/8 192.168.0.0/16).
        /// Use "0.0.0.0/0 ::/0" to restore open access.
        cidrs: Vec<String>,
    },
}

pub fn run(config_path: &Path, args: WebuiArgs) -> anyhow::Result<()> {
    match args.action {
        WebuiAction::Show => {
            let config = load_config(config_path)?;
            let w = &config.webui;
            if args.json {
                println!("{}", serde_json::json!({
                    "enabled": w.enabled,
                    "listen": w.listen,
                    "tls_cert": w.tls_cert,
                    "tls_key": w.tls_key,
                    "tokens_file": w.tokens_file,
                    "web_users_file": w.web_users_file,
                    "allowed_origins": w.allowed_origins,
                    "allow_list": w.allow_list,
                }));
                return Ok(());
            }
            println!("Enabled:        {}", w.enabled);
            println!("Listen:         {}", w.listen);
            println!("TLS Cert:       {}", w.tls_cert.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "(none)".into()));
            println!("TLS Key:        {}", w.tls_key.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "(none)".into()));
            println!("Tokens File:    {}", w.tokens_file.display());
            println!("Web Users File: {}", w.web_users_file.display());
            if w.allowed_origins.is_empty() {
                println!("CORS Origins:   (any)");
            } else {
                println!("CORS Origins:   {}", w.allowed_origins.join(", "));
            }
            if w.allow_list.is_empty() {
                println!("IP Allowlist:   (none — all connections rejected!)");
            } else {
                println!("IP Allowlist:   {}", w.allow_list.join(", "));
            }
        }

        WebuiAction::SetConfig { enabled, listen, tls_cert, tls_key, tokens_file, web_users_file } => {
            let config = load_config(config_path)?;
            let mut w = config.webui.clone();
            if let Some(v) = enabled  { w.enabled = v; }
            if let Some(v) = listen   { w.listen = v; }
            if let Some(v) = tls_cert { w.tls_cert = if v.is_empty() { None } else { Some(v.into()) }; }
            if let Some(v) = tls_key  { w.tls_key  = if v.is_empty() { None } else { Some(v.into()) }; }
            if let Some(v) = tokens_file    { w.tokens_file = v.into(); }
            if let Some(v) = web_users_file { w.web_users_file = v.into(); }
            editor::update_webui_config(config_path, w)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("WebUI configuration updated. Restart serverwall-webui for connection changes to take effect.");
            reload_webui();
        }

        WebuiAction::AddOrigin { origin } => {
            let config = load_config(config_path)?;
            let mut w = config.webui.clone();
            if w.allowed_origins.contains(&origin) {
                println!("'{}' already in CORS origins list.", origin);
                return Ok(());
            }
            w.allowed_origins.push(origin.clone());
            editor::update_webui_config(config_path, w)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("CORS origin '{}' added.", origin);
            reload_webui();
        }

        WebuiAction::RemoveOrigin { origin } => {
            let config = load_config(config_path)?;
            let mut w = config.webui.clone();
            let before = w.allowed_origins.len();
            w.allowed_origins.retain(|o| o != &origin);
            if w.allowed_origins.len() == before {
                anyhow::bail!("'{}' not found in CORS origins list.", origin);
            }
            editor::update_webui_config(config_path, w)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("CORS origin '{}' removed.", origin);
            reload_webui();
        }

        WebuiAction::ListOrigins => {
            let config = load_config(config_path)?;
            if config.webui.allowed_origins.is_empty() {
                println!("No CORS origins configured (all origins allowed).");
            } else {
                for o in &config.webui.allowed_origins {
                    println!("{}", o);
                }
            }
        }

        WebuiAction::List => {
            let config = load_config(config_path)?;
            let list = &config.webui.allow_list;

            if args.json {
                println!("{}", serde_json::to_string_pretty(list)?);
                return Ok(());
            }

            if list.is_empty() {
                println!("WebUI IP allowlist is empty (all connections will be rejected).");
                return Ok(());
            }

            let rows: Vec<Vec<String>> = list.iter().map(|c| vec![c.clone()]).collect();
            output::print_table(&["CIDR"], &rows);
        }

        WebuiAction::Add { cidr } => {
            IpMatcher::new(&[cidr.clone()])
                .map_err(|e| anyhow::anyhow!("invalid CIDR '{}': {}", cidr, e))?;

            let mut config = load_config(config_path)?;
            if config.webui.allow_list.contains(&cidr) {
                println!("{} is already in the WebUI allowlist.", cidr);
                return Ok(());
            }
            config.webui.allow_list.push(cidr.clone());
            editor::update_webui_allow_list(config_path, config.webui.allow_list)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Added {} to WebUI allowlist.", cidr);
            reload_webui();
        }

        WebuiAction::Remove { cidr } => {
            let mut config = load_config(config_path)?;
            let before = config.webui.allow_list.len();
            config.webui.allow_list.retain(|c| c != &cidr);
            if config.webui.allow_list.len() == before {
                anyhow::bail!("{} not found in WebUI allowlist", cidr);
            }
            editor::update_webui_allow_list(config_path, config.webui.allow_list)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Removed {} from WebUI allowlist.", cidr);
            reload_webui();
        }

        WebuiAction::Set { cidrs } => {
            IpMatcher::new(&cidrs)
                .map_err(|e| anyhow::anyhow!("invalid CIDR in list: {}", e))?;
            editor::update_webui_allow_list(config_path, cidrs.clone())
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("WebUI allowlist set to: {}", cidrs.join(", "));
            reload_webui();
        }
    }
    Ok(())
}

/// Send SIGHUP to the webui process to trigger a live config reload.
fn reload_webui() {
    match send_reload_signal(&PathBuf::from(DEFAULT_WEBUI_PID_FILE)) {
        Ok(()) => println!("Reload signal sent to serverwall-webui."),
        Err(e) => eprintln!(
            "Warning: config updated but could not signal webui: {}\n\
             The new settings will take effect on next webui restart.",
            e
        ),
    }
}
