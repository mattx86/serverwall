use std::path::Path;

use clap::Args;

use serverwall_core::config::load_config;

#[derive(Args)]
pub struct StatusArgs {
    /// Output as JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

pub fn run(config_path: &Path, args: StatusArgs) -> anyhow::Result<()> {
    let config = load_config(config_path)?;

    if args.json {
        let json = serde_json::json!({
            "config_path": config_path.display().to_string(),
            "frontend_count": config.frontend.len(),
            "backend_pool_count": config.backend_pool.len(),
            "relay_enabled": config.relay.enabled,
            "antispam_enabled": config.antispam.enabled,
            "webui_enabled": config.webui.enabled,
            "webui_listen": config.webui.listen,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("ServerWall Status");
    println!("=================");
    println!("Config:           {}", config_path.display());
    println!("Frontends:        {}", config.frontend.len());
    println!("Backend Pools:    {}", config.backend_pool.len());
    println!("Relay Enabled:    {}", config.relay.enabled);
    println!("Antispam Enabled: {}", config.antispam.enabled);
    println!("Web UI Enabled:   {}", config.webui.enabled);
    println!("Web UI Listen:    {}", config.webui.listen);

    if !config.frontend.is_empty() {
        println!();
        println!("Frontends:");
        for f in &config.frontend {
            println!("  {} ({}) -> {}", f.name, format!("{:?}", f.protocol).to_lowercase(), f.backend_pool);
        }
    }

    Ok(())
}
