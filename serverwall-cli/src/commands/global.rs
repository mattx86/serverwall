use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::schema::GlobalConfig;

use crate::commands::maybe_reload;

#[derive(Args)]
pub struct GlobalArgs {
    #[command(subcommand)]
    pub action: GlobalAction,
}

#[derive(Subcommand)]
pub enum GlobalAction {
    /// Show current global daemon settings.
    Show,
    /// Update global daemon settings (only specified flags are changed).
    Set {
        /// Daemon name shown in logs and process title.
        #[arg(long)]
        daemon_name: Option<String>,
        /// Worker thread count (0 = one per CPU).
        #[arg(long)]
        worker_threads: Option<usize>,
        /// Maximum simultaneous connections (0 = unlimited).
        #[arg(long)]
        max_connections: Option<usize>,
        /// Directory for log files.
        #[arg(long)]
        log_dir: Option<String>,
        /// Directory for TLS certificates.
        #[arg(long)]
        cert_dir: Option<String>,
        /// Drop-in config directory (conf.d/).
        #[arg(long)]
        config_dir: Option<String>,
        /// Log level: error, warn, info, debug, or trace.
        #[arg(long)]
        log_level: Option<String>,
        /// Seconds to drain active connections on graceful shutdown (0 = exit immediately).
        #[arg(long)]
        drain_secs: Option<u64>,
    },
}

pub fn run(config_path: &Path, args: GlobalArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        GlobalAction::Show => {
            let config = load_config(config_path)?;
            let g = &config.global;
            println!("Daemon Name:    {}", g.daemon_name);
            println!("Worker Threads: {} (0 = auto)", g.worker_threads);
            println!("Max Connections:{} (0 = unlimited)", g.max_connections);
            println!("Log Dir:        {}", g.log_dir.display());
            println!("Cert Dir:       {}", g.cert_dir.display());
            if let Some(ref d) = g.config_dir {
                println!("Config Dir:     {}", d.display());
            }
            if let Some(ref p) = g.pid_file {
                println!("PID File:       {}", p.display());
            }
            println!("Log Level:      {}", g.log_level);
            println!("Drain Secs:     {}", g.graceful_drain_secs);
        }

        GlobalAction::Set {
            daemon_name, worker_threads, max_connections,
            log_dir, cert_dir, config_dir, log_level, drain_secs,
        } => {
            let config = load_config(config_path)?;
            let mut g: GlobalConfig = config.global.clone();
            if let Some(v) = daemon_name       { g.daemon_name = v; }
            if let Some(v) = worker_threads    { g.worker_threads = v; }
            if let Some(v) = max_connections   { g.max_connections = v; }
            if let Some(v) = log_dir           { g.log_dir = v.into(); }
            if let Some(v) = cert_dir          { g.cert_dir = v.into(); }
            if let Some(v) = log_level         { g.log_level = v; }
            if let Some(v) = drain_secs        { g.graceful_drain_secs = v; }
            g.config_dir = config_dir.map(Into::into).or(config.global.config_dir);
            editor::update_global_config(config_path, g)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Global settings updated.");
            maybe_reload(no_reload);
        }
    }
    Ok(())
}
