pub mod frontend;
pub mod backend;
pub mod cert;
pub mod acl;
pub mod waf;
pub mod status;
pub mod queue;
pub mod dkim;
pub mod antispam;
pub mod reload;
pub mod webui;
pub mod global;
pub mod acme;
pub mod security;
pub mod security_profile;
pub mod log_profile;
pub mod relay;
pub mod dmarc;
pub mod spf;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum Command {
    /// Show system status.
    Status(status::StatusArgs),
    /// Manage frontends.
    Frontend(frontend::FrontendArgs),
    /// Manage backend pools and servers.
    Backend(backend::BackendArgs),
    /// Manage the mail queue.
    Queue(queue::QueueArgs),
    /// Manage TLS certificates.
    Cert(cert::CertArgs),
    /// Manage access control lists.
    Acl(acl::AclArgs),
    /// Manage WAF rulesets.
    Waf(waf::WafArgs),
    /// Manage DKIM keys and signing.
    Dkim(dkim::DkimArgs),
    /// Antispam configuration and list management.
    Antispam(antispam::AntispamArgs),
    /// Reload the daemon configuration (sends SIGHUP).
    Reload(reload::ReloadArgs),
    /// Manage WebUI access and configuration.
    Webui(webui::WebuiArgs),
    /// Show and update global daemon settings.
    Global(global::GlobalArgs),
    /// Show and update ACME / Let's Encrypt settings.
    Acme(acme::AcmeArgs),
    /// Manage global security settings (TLS, GeoIP, ACL, headers, etc.).
    Security(security::SecurityArgs),
    /// Manage security profiles.
    SecurityProfile(security_profile::SecurityProfileArgs),
    /// Manage logging profiles.
    LogProfile(log_profile::LogProfileArgs),
    /// Manage the SMTP relay configuration.
    Relay(relay::RelayArgs),
    /// Manage DMARC policy publishing.
    Dmarc(dmarc::DmarcArgs),
    /// Manage SPF record publishing.
    Spf(spf::SpfArgs),
}

/// Send reload signal unless --no-reload was passed.
pub fn maybe_reload(no_reload: bool) {
    if no_reload {
        return;
    }
    let pid_file = std::path::PathBuf::from(serverwall_core::DEFAULT_PID_FILE);
    match serverwall_core::send_reload_signal(&pid_file) {
        Ok(()) => println!("Reload signal sent to serverwall daemon."),
        Err(e) => eprintln!(
            "Warning: config written but could not reload daemon: {}\n\
             Run `serverwallctl reload` manually or restart serverwall.",
            e
        ),
    }
}
