use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct RelayArgs {
    #[command(subcommand)]
    pub action: RelayAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum RelayAction {
    /// Show relay configuration.
    Show,
    /// Update top-level relay settings (only specified flags are changed).
    Set {
        /// Enable or disable the outbound relay.
        #[arg(long)]
        enabled: Option<bool>,
        /// SMTP EHLO hostname announced to remote servers.
        #[arg(long)]
        hostname: Option<String>,
        /// Listen addresses for trusted relay submissions (e.g. 127.0.0.1:2525).
        #[arg(long, value_delimiter = ',')]
        listen: Option<Vec<String>>,
        /// Directory used for the mail spool.
        #[arg(long)]
        spool_dir: Option<String>,
        /// Maximum number of messages in the queue.
        #[arg(long)]
        max_queue_size: Option<usize>,
        /// Number of concurrent delivery threads.
        #[arg(long)]
        delivery_threads: Option<usize>,
    },
    /// Update outbound TLS settings.
    SetTls {
        /// Use opportunistic TLS (STARTTLS) when available.
        #[arg(long)]
        opportunistic: Option<bool>,
        /// Verify remote server TLS certificates.
        #[arg(long)]
        verify_certificates: Option<bool>,
        /// Minimum TLS version: 1.2 or 1.3.
        #[arg(long)]
        min_version: Option<String>,
    },
    /// Update retry settings.
    SetRetry {
        /// Comma-separated retry intervals (e.g. 5m,15m,1h,4h,8h).
        #[arg(long, value_delimiter = ',')]
        intervals: Option<Vec<String>>,
        /// Maximum age before a message is bounced (e.g. 5d).
        #[arg(long)]
        max_age: Option<String>,
        /// Maximum delivery attempts before bounce.
        #[arg(long)]
        max_attempts: Option<u32>,
    },
    /// Update outbound policy settings.
    SetOutbound {
        /// Enable outbound policy enforcement.
        #[arg(long)]
        enabled: Option<bool>,
        /// Maximum message size in bytes.
        #[arg(long)]
        max_message_size: Option<usize>,
        /// Maximum recipients per message.
        #[arg(long)]
        max_recipients: Option<usize>,
        /// Comma-separated list of allowed sender domains.
        #[arg(long, value_delimiter = ',')]
        allowed_sender_domains: Option<Vec<String>>,
        /// Maximum messages per domain per hour.
        #[arg(long)]
        max_per_domain_per_hour: Option<u64>,
        /// Block messages with dangerous attachments (.exe, .bat, etc.).
        #[arg(long)]
        block_dangerous_attachments: Option<bool>,
        /// Check URLs in messages against SURBL.
        #[arg(long)]
        check_urls: Option<bool>,
    },
    /// Update bounce message settings.
    SetBounce {
        /// Envelope sender for bounce messages (empty = use postmaster@hostname).
        #[arg(long)]
        sender: Option<String>,
        /// Include original message headers in bounces.
        #[arg(long)]
        include_original_headers: Option<bool>,
    },
    /// Add a trusted host CIDR to the relay.
    AddTrustedHost {
        /// IP address or CIDR range trusted to submit mail.
        cidr: String,
    },
    /// Remove a trusted host CIDR from the relay.
    RemoveTrustedHost {
        /// IP address or CIDR to remove.
        cidr: String,
    },
    /// Set whether trusted hosts must use TLS.
    SetTrustedHostsTls {
        /// Require TLS for trusted host connections.
        #[arg(long)]
        require_tls: bool,
    },
    /// List trusted relay submission hosts.
    ListTrustedHosts,
}

pub fn run(config_path: &Path, args: RelayArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        RelayAction::Show => {
            let config = load_config(config_path)?;
            let r = &config.relay;
            if args.json {
                println!("{}", serde_json::to_string_pretty(r)?);
                return Ok(());
            }
            println!("Enabled:          {}", r.enabled);
            println!("Hostname:         {}", r.hostname.as_deref().unwrap_or("(auto)"));
            println!("Listen:           {}", r.listen.join(", "));
            println!("Spool Dir:        {}", r.spool_dir.display());
            println!("Max Queue:        {}", r.max_queue_size);
            println!("Delivery Threads: {}", r.delivery_threads);
            println!();
            println!("=== Trusted Hosts ===");
            println!("  Require TLS: {}", r.trusted_hosts.require_tls);
            if r.trusted_hosts.hosts.is_empty() {
                println!("  Hosts: (none)");
            } else {
                for h in &r.trusted_hosts.hosts { println!("  - {}", h); }
            }
            println!();
            println!("=== Retry ===");
            println!("  Intervals:    {}", r.retry.intervals.join(", "));
            println!("  Max Age:      {}", r.retry.max_age);
            println!("  Max Attempts: {}", r.retry.max_attempts);
            println!();
            println!("=== Outbound TLS ===");
            println!("  Opportunistic:    {}", r.tls.opportunistic);
            println!("  Verify Certs:     {}", r.tls.verify_certificates);
            println!("  Min Version:      {}", r.tls.min_version);
            println!();
            println!("=== Outbound Policy ===");
            println!("  Enabled:              {}", r.outbound_policy.enabled);
            println!("  Max Message Size:     {} bytes", r.outbound_policy.max_message_size);
            println!("  Max Recipients:       {}", r.outbound_policy.max_recipients_per_message);
            println!("  Max/Domain/Hour:      {}", r.outbound_policy.max_messages_per_domain_per_hour);
            println!("  Block Dangerous Att.: {}", r.outbound_policy.block_dangerous_attachments);
            println!("  Check URLs:           {}", r.outbound_policy.check_urls);
            if !r.outbound_policy.allowed_sender_domains.is_empty() {
                println!("  Allowed Senders:  {}", r.outbound_policy.allowed_sender_domains.join(", "));
            }
            println!();
            println!("=== Bounce ===");
            println!("  Sender:               {}", r.bounce.sender.as_deref().unwrap_or("(auto)"));
            println!("  Include Orig Headers: {}", r.bounce.include_original_headers);
        }

        RelayAction::Set { enabled, hostname, listen, spool_dir, max_queue_size, delivery_threads } => {
            let config = load_config(config_path)?;
            let mut r = config.relay.clone();
            if let Some(v) = enabled          { r.enabled = v; }
            if let Some(v) = listen           { r.listen = v; }
            if let Some(v) = spool_dir        { r.spool_dir = v.into(); }
            if let Some(v) = max_queue_size   { r.max_queue_size = v; }
            if let Some(v) = delivery_threads { r.delivery_threads = v; }
            r.hostname = match hostname {
                Some(ref s) if s.is_empty() => None,
                Some(s) => Some(s),
                None => r.hostname,
            };
            editor::set_relay_config(config_path, r)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Relay settings updated.");
            maybe_reload(no_reload);
        }

        RelayAction::SetTls { opportunistic, verify_certificates, min_version } => {
            let config = load_config(config_path)?;
            let mut r = config.relay.clone();
            if let Some(v) = opportunistic       { r.tls.opportunistic = v; }
            if let Some(v) = verify_certificates { r.tls.verify_certificates = v; }
            if let Some(v) = min_version         { r.tls.min_version = v; }
            editor::set_relay_config(config_path, r)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Relay TLS settings updated.");
            maybe_reload(no_reload);
        }

        RelayAction::SetRetry { intervals, max_age, max_attempts } => {
            let config = load_config(config_path)?;
            let mut r = config.relay.clone();
            if let Some(v) = intervals    { r.retry.intervals = v; }
            if let Some(v) = max_age      { r.retry.max_age = v; }
            if let Some(v) = max_attempts { r.retry.max_attempts = v; }
            editor::set_relay_config(config_path, r)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Relay retry settings updated.");
            maybe_reload(no_reload);
        }

        RelayAction::SetOutbound {
            enabled, max_message_size, max_recipients, allowed_sender_domains,
            max_per_domain_per_hour, block_dangerous_attachments, check_urls,
        } => {
            let config = load_config(config_path)?;
            let mut r = config.relay.clone();
            let p = &mut r.outbound_policy;
            if let Some(v) = enabled                    { p.enabled = v; }
            if let Some(v) = max_message_size           { p.max_message_size = v; }
            if let Some(v) = max_recipients             { p.max_recipients_per_message = v; }
            if let Some(v) = allowed_sender_domains     { p.allowed_sender_domains = v; }
            if let Some(v) = max_per_domain_per_hour    { p.max_messages_per_domain_per_hour = v; }
            if let Some(v) = block_dangerous_attachments{ p.block_dangerous_attachments = v; }
            if let Some(v) = check_urls                 { p.check_urls = v; }
            editor::set_relay_config(config_path, r)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Outbound policy settings updated.");
            maybe_reload(no_reload);
        }

        RelayAction::SetBounce { sender, include_original_headers } => {
            let config = load_config(config_path)?;
            let mut r = config.relay.clone();
            if let Some(ref s) = sender {
                r.bounce.sender = if s.is_empty() { None } else { Some(s.clone()) };
            }
            if let Some(v) = include_original_headers { r.bounce.include_original_headers = v; }
            editor::set_relay_config(config_path, r)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Bounce settings updated.");
            maybe_reload(no_reload);
        }

        RelayAction::AddTrustedHost { cidr } => {
            editor::add_trusted_host(config_path, cidr.clone())
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Trusted host '{}' added.", cidr);
            maybe_reload(no_reload);
        }

        RelayAction::RemoveTrustedHost { cidr } => {
            editor::remove_trusted_host(config_path, &cidr)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Trusted host '{}' removed.", cidr);
            maybe_reload(no_reload);
        }

        RelayAction::SetTrustedHostsTls { require_tls } => {
            let config = load_config(config_path)?;
            let mut r = config.relay.clone();
            r.trusted_hosts.require_tls = require_tls;
            editor::set_relay_config(config_path, r)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Trusted hosts TLS requirement set to {}.", require_tls);
            maybe_reload(no_reload);
        }

        RelayAction::ListTrustedHosts => {
            let config = load_config(config_path)?;
            let th = &config.relay.trusted_hosts;
            println!("Require TLS: {}", th.require_tls);
            if th.hosts.is_empty() {
                println!("No trusted hosts configured.");
            } else {
                let rows: Vec<Vec<String>> = th.hosts.iter().map(|h| vec![h.clone()]).collect();
                output::print_table(&["HOST/CIDR"], &rows);
            }
        }
    }
    Ok(())
}
