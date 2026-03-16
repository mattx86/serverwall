mod commands;
mod output;

use std::path::PathBuf;

use clap::Parser;
use commands::Command;
use serverwall_core::DEFAULT_CONFIG_PATH;

/// serverwallctl - CLI management tool for ServerWall.
///
/// Reads and writes /opt/serverwall/etc/serverwall.toml directly.
/// Does not require the web UI to be running.
#[derive(Parser)]
#[command(name = "serverwallctl", version, about)]
pub struct Cli {
    /// Path to the configuration file.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: PathBuf,

    /// Skip sending reload signal to the daemon after config changes.
    #[arg(long)]
    pub no_reload: bool,

    #[command(subcommand)]
    pub command: Command,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Status(args) => commands::status::run(&cli.config, args),
        Command::Frontend(args) => commands::frontend::run(&cli.config, args, cli.no_reload),
        Command::Backend(args) => commands::backend::run(&cli.config, args, cli.no_reload),
        Command::Queue(args) => commands::queue::run(&cli.config, args),
        Command::Cert(args) => commands::cert::run(&cli.config, args),
        Command::Acl(args) => commands::acl::run(&cli.config, args, cli.no_reload),
        Command::Waf(args) => commands::waf::run(&cli.config, args, cli.no_reload),
        Command::Dkim(args) => commands::dkim::run(&cli.config, args, cli.no_reload),
        Command::Antispam(args) => commands::antispam::run(&cli.config, args),
        Command::Reload(_) => commands::reload::run(cli.no_reload),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
