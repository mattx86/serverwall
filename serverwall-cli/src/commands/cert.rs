use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::load_config;

use crate::output;

#[derive(Args)]
pub struct CertArgs {
    #[command(subcommand)]
    pub action: CertAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum CertAction {
    /// List TLS certificates in the cert directory.
    List,
    /// Import a PEM certificate file into the cert directory.
    Import {
        /// Path to the PEM file to import.
        path: String,
        /// Destination filename (default: basename of source).
        #[arg(long)]
        name: Option<String>,
    },
}

pub fn run(config_path: &Path, args: CertArgs) -> anyhow::Result<()> {
    let config = load_config(config_path)?;
    let cert_dir = &config.global.cert_dir;

    match args.action {
        CertAction::List => {
            let entries = std::fs::read_dir(cert_dir)
                .map_err(|e| anyhow::anyhow!("failed to read cert dir {}: {}", cert_dir.display(), e))?;

            let mut rows: Vec<Vec<String>> = Vec::new();
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if !matches!(ext, "pem" | "crt" | "cer" | "pfx" | "p12") {
                    continue;
                }
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let modified = entry.metadata()
                    .and_then(|m| m.modified())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Utc> = t.into();
                        dt.format("%Y-%m-%d %H:%M").to_string()
                    })
                    .unwrap_or_else(|_| "-".to_string());
                rows.push(vec![name, format_size(size), modified]);
            }

            if args.json {
                let json: Vec<_> = rows.iter().map(|r| serde_json::json!({
                    "name": r[0],
                    "size": r[1],
                    "modified": r[2],
                })).collect();
                println!("{}", serde_json::to_string_pretty(&json)?);
                return Ok(());
            }

            println!("Cert directory: {}", cert_dir.display());
            println!();
            if rows.is_empty() {
                println!("No certificates found.");
            } else {
                output::print_table(&["NAME", "SIZE", "MODIFIED"], &rows);
            }
        }

        CertAction::Import { path, name } => {
            let src = std::path::PathBuf::from(&path);
            if !src.exists() {
                anyhow::bail!("file not found: {}", path);
            }
            let dest_name = name.unwrap_or_else(|| {
                src.file_name().and_then(|n| n.to_str()).unwrap_or("cert.pem").to_string()
            });
            std::fs::create_dir_all(cert_dir)
                .map_err(|e| anyhow::anyhow!("failed to create cert dir: {}", e))?;
            let dest = cert_dir.join(&dest_name);
            std::fs::copy(&src, &dest)
                .map_err(|e| anyhow::anyhow!("failed to copy cert: {}", e))?;
            println!("Imported {} → {}", path, dest.display());
            println!("Run `serverwallctl reload` to apply.");
        }
    }
    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    }
}
