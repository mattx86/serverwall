use std::path::PathBuf;

use clap::Args;

use serverwall_core::{send_reload_signal, DEFAULT_PID_FILE};

#[derive(Args)]
pub struct ReloadArgs {}

pub fn run(no_reload: bool) -> anyhow::Result<()> {
    if no_reload {
        println!("Skipped (--no-reload).");
        return Ok(());
    }

    let pid_file = PathBuf::from(DEFAULT_PID_FILE);
    send_reload_signal(&pid_file).map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Reload signal sent to serverwall daemon.");
    Ok(())
}
