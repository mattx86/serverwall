mod listener;
mod pipeline;
mod proxy;
mod reload;
mod server;

use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use serverwall_core::config::{defaults, editor, load_config, schema::{WafExclusions, WafMode, WafRulesetConfig}};
use serverwall_core::DEFAULT_CONFIG_PATH;

/// ServerWall reverse proxy and load balancer.
#[derive(Parser, Debug)]
#[command(name = "serverwall", version, about)]
pub struct Args {
    /// Path to the configuration file.
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Initialize default configuration, admin user, and exit.
    #[arg(long)]
    init: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the ring crypto provider for rustls before any TLS operations.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let args = Args::parse();

    if args.init {
        return run_init();
    }

    // Load configuration
    let config = load_config(&args.config)
        .map_err(|e| anyhow::anyhow!("failed to load config: {}", e))?;

    // Initialize tracing — stdout (ANSI) + file (no ANSI)
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.global.log_level));

    let file_appender = tracing_appender::rolling::never(&config.global.log_dir, "serverwall.log");
    let (non_blocking, _file_guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout).with_ansi(true).with_target(true).with_thread_ids(true))
        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking).with_ansi(false).with_target(true).with_thread_ids(true))
        .init();

    tracing::info!(
        config_path = %args.config.display(),
        frontends = config.frontend.len(),
        pools = config.backend_pool.len(),
        "starting serverwall-proxy",
    );

    // Create and run the server
    let server = server::Server::from_config(config, args.config);
    server.run().await?;

    Ok(())
}

/// First-run initialization.
///
/// 1. Create /opt/serverwall/ directory structure
/// 2. Generate a self-signed TLS certificate for the web UI
/// 3. Generate default serverwall.toml config
/// 4. Generate a random 32-char admin password, hash with argon2
/// 5. Write web-users.toml with admin user
/// 6. Write empty api-tokens.toml
/// 7. Print the admin credentials to stdout
fn run_init() -> anyhow::Result<()> {
    let base = PathBuf::from("/opt/serverwall");
    let etc_dir = base.join("etc");
    let certs_dir = etc_dir.join("certs");
    let acme_dir = etc_dir.join("acme");
    let dkim_dir = etc_dir.join("dkim");
    let run_dir = base.join("run");
    let spool_dir = base.join("var/spool");
    let log_dir = base.join("var/log");
    let lib_dir = base.join("var/lib");

    // 1. Create directory structure
    for dir in &[&etc_dir, &certs_dir, &acme_dir, &dkim_dir, &run_dir, &spool_dir, &log_dir, &lib_dir] {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("failed to create directory {}: {}", dir.display(), e))?;
    }

    // 2. Generate self-signed TLS certificate for the web UI
    let webui_cert = certs_dir.join("webui.pem");
    let webui_key = certs_dir.join("webui-key.pem");
    let hostname = get_hostname();
    if !webui_cert.exists() || !webui_key.exists() {
        let extra_ips = collect_local_ips();
        serverwall_core::tls::generate_self_signed_cert(&webui_cert, &webui_key, &hostname, &extra_ips)?;
        println!("Created: {} (self-signed TLS cert)", webui_cert.display());
        println!("Created: {}", webui_key.display());
    } else {
        println!("Exists:  {} (not overwritten)", webui_cert.display());
    }

    // 3. Generate default config
    let config_path = etc_dir.join("serverwall.toml");
    if !config_path.exists() {
        let default_config = defaults::generate_default_config();
        std::fs::write(&config_path, default_config)?;
        println!("Created: {}", config_path.display());
    } else {
        println!("Exists:  {} (not overwritten)", config_path.display());
    }

    // 3b. Ensure "default" WAF ruleset exists
    let _ = editor::add_waf_ruleset(&config_path, WafRulesetConfig {
        name: "default".to_string(),
        mode: WafMode::Blocking,
        anomaly_threshold: 5,
        paranoia_level: 1,
        rules_dir: None,
        exclusions: WafExclusions::default(),
        custom_rules: vec![],
    });

    // 4. Generate a random 32-character admin password and hash it
    let admin_password = generate_random_password(32);
    let password_hash = hash_password(&admin_password)?;

    // 5. Write web-users.toml with admin user
    let users_path = etc_dir.join("web-users.toml");
    let users_content = format!(
        "# ServerWall Web Users\n\
         # Passwords are hashed with argon2id.\n\
         # Use `serverwall --init` to regenerate.\n\
         \n\
         [[user]]\n\
         username = \"admin\"\n\
         password_hash = \"{}\"\n",
        password_hash
    );
    std::fs::write(&users_path, users_content)?;
    println!("Created: {}", users_path.display());

    // 6. Write empty api-tokens.toml
    let tokens_path = etc_dir.join("api-tokens.toml");
    let tokens_content = "# ServerWall API Tokens\n\
        # Each token is hashed with argon2id.\n\
        #\n\
        # [[token]]\n\
        # name = \"my-integration\"\n\
        # hash = \"$argon2id$...\"\n";
    std::fs::write(&tokens_path, tokens_content)?;
    println!("Created: {}", tokens_path.display());

    // 7. Print credentials in a visible box
    println!();
    println!("+{}+", "-".repeat(62));
    println!("|{:^62}|", "");
    println!("|{:^62}|", "ServerWall Initial Setup Complete");
    println!("|{:^62}|", "");
    println!("+{}+", "-".repeat(62));
    println!("|{:^62}|", "");
    println!("| {:<60} |", "Web UI Credentials:");
    println!("|{:^62}|", "");
    println!("| {:<60} |", "  Username: admin");
    println!("| {:<60} |", format!("  Password: {}", admin_password));
    println!("|{:^62}|", "");
    println!("| {:<60} |", format!("Web UI:   https://{}:8443 (self-signed TLS)", hostname));
    println!("| {:<60} |", format!("Config:   {}", config_path.display()));
    println!("| {:<60} |", format!("Users:    {}", users_path.display()));
    println!("| {:<60} |", format!("Tokens:   {}", tokens_path.display()));
    println!("|{:^62}|", "");
    println!("| {:<60} |", "Save this password now. It cannot be recovered.");
    println!("|{:^62}|", "");
    println!("+{}+", "-".repeat(62));

    Ok(())
}

/// Generate a random alphanumeric password of the given length.
fn generate_random_password(len: usize) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();

    let mut password = String::with_capacity(len);
    for i in 0..len {
        // Use UUID v4 for randomness since we have it as a dependency
        let uuid_val = uuid::Uuid::new_v4();
        let bytes = uuid_val.as_bytes();
        let idx = (bytes[i % 16] as usize) % chars.len();
        password.push(chars[idx]);
    }
    password
}

/// Collect all non-loopback IPv4 addresses on the local machine.
fn collect_local_ips() -> Vec<std::net::IpAddr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|iface| {
            let ip = iface.addr.ip();
            if ip.is_loopback() { None } else { Some(ip) }
        })
        .collect()
}

/// Return the system hostname, reading from /etc/hostname.
/// Falls back to "localhost" if unavailable.
fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

/// Hash a password with argon2id.
fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::password_hash::rand_core::OsRng;
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash password: {}", e))?;

    Ok(hash.to_string())
}
