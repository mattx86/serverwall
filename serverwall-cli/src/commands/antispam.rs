use std::path::Path;

use clap::Args;

use serverwall_core::config::load_config;

#[derive(Args)]
pub struct AntispamArgs {
    /// Output as JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

pub fn run(config_path: &Path, args: AntispamArgs) -> anyhow::Result<()> {
    let config = load_config(config_path)?;
    let a = &config.antispam;

    if args.json {
        let json = serde_json::json!({
            "enabled": a.enabled,
            "possible_spam_threshold": a.possible_spam_threshold,
            "definite_spam_threshold": a.definite_spam_threshold,
            "max_check_duration": a.max_check_duration,
            "checks": {
                "dnsbl": a.dnsbl.enabled,
                "spf": a.spf.enabled,
                "dkim": a.dkim.enabled,
                "dmarc": a.dmarc.enabled,
                "content": a.content.enabled,
                "url_analysis": a.url_analysis.enabled,
                "attachment": a.attachment.enabled,
                "html": a.html.enabled,
                "rdns": a.rdns.enabled,
                "helo": a.helo.enabled,
                "antivirus": a.antivirus.enabled,
            }
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("Antispam Configuration");
    println!("======================");
    println!("Enabled:         {}", a.enabled);
    println!("Possible Spam:   {}%", a.possible_spam_threshold);
    println!("Definite Spam:   {}%", a.definite_spam_threshold);
    println!("Max Duration:    {}", a.max_check_duration);
    println!();
    println!("Checks:");
    println!("  {:<16} {}", "dnsbl",        yn(a.dnsbl.enabled));
    println!("  {:<16} {}", "spf",          yn(a.spf.enabled));
    println!("  {:<16} {}", "dkim",         yn(a.dkim.enabled));
    println!("  {:<16} {}", "dmarc",        yn(a.dmarc.enabled));
    println!("  {:<16} {}", "content",      yn(a.content.enabled));
    println!("  {:<16} {}", "url_analysis", yn(a.url_analysis.enabled));
    println!("  {:<16} {}", "attachment",   yn(a.attachment.enabled));
    println!("  {:<16} {}", "html",         yn(a.html.enabled));
    println!("  {:<16} {}", "rdns",         yn(a.rdns.enabled));
    println!("  {:<16} {}", "helo",         yn(a.helo.enabled));
    println!("  {:<16} {}", "antivirus",    yn(a.antivirus.enabled));

    Ok(())
}

fn yn(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}
