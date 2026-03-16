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

use clap::Subcommand;

#[derive(Subcommand)]
pub enum Command {
    /// Show system status.
    Status(status::StatusArgs),
    /// Manage frontends.
    Frontend(frontend::FrontendArgs),
    /// Manage backends.
    Backend(backend::BackendArgs),
    /// Manage the mail queue.
    Queue(queue::QueueArgs),
    /// Manage TLS certificates.
    Cert(cert::CertArgs),
    /// Manage access control lists.
    Acl(acl::AclArgs),
    /// Manage WAF rules.
    Waf(waf::WafArgs),
    /// Manage DKIM keys and signing.
    Dkim(dkim::DkimArgs),
    /// Antispam statistics and configuration.
    Antispam(antispam::AntispamArgs),
    /// Reload the daemon configuration (sends SIGHUP).
    Reload(reload::ReloadArgs),
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
