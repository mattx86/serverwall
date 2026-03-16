mod listener;
mod metrics;
mod pipeline;
mod proxy;
mod reload;
mod server;

use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use serverwall_core::config::{defaults, load_config};
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
    let args = Args::parse();

    if args.init {
        return run_init();
    }

    // Load configuration
    let config = load_config(&args.config)
        .map_err(|e| anyhow::anyhow!("failed to load config: {}", e))?;

    // Initialize tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.global.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    tracing::info!(
        config_path = %args.config.display(),
        frontends = config.frontend.len(),
        pools = config.backend_pool.len(),
        "starting serverwall-proxy",
    );

    // Create and run the server
    let server = server::Server::from_config(config);
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
        generate_self_signed_cert(&webui_cert, &webui_key, &hostname)?;
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

/// Generate a self-signed X.509 certificate using the openssl crate.
fn generate_self_signed_cert(cert_path: &PathBuf, key_path: &PathBuf, cn: &str) -> anyhow::Result<()> {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder};
    use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};

    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", cn)?;
    let name = name.build();

    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?; // 10 years

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.set_pubkey(&pkey)?;

    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(basic_constraints)?;

    let san = SubjectAlternativeName::new()
        .dns(cn)
        .dns("localhost")
        .ip("127.0.0.1")
        .build(&builder.x509v3_context(None, None))?;
    builder.append_extension(san)?;

    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = builder.build();

    // Write certificate PEM
    let cert_pem = cert.to_pem()?;
    std::fs::write(cert_path, &cert_pem)?;

    // Write private key PEM (mode 0600 on Unix)
    let key_pem = pkey.private_key_to_pem_pkcs8()?;
    std::fs::write(key_path, &key_pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    }

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
