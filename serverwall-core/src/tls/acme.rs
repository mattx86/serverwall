use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::acl::IpMatcher;
use crate::config::AcmeConfig;
use crate::error::Result as CoreResult;

/// A callable that inspects an HTTP request and returns `true` if it should be blocked.
/// Arguments: method, uri, peer_ip, headers (lowercase names).
pub type WafFn = Arc<dyn Fn(&str, &str, std::net::IpAddr, &HashMap<String, String>) -> bool + Send + Sync>;

/// Manages automatic certificate provisioning via the ACME protocol.
pub struct AcmeManager {
    /// Whether ACME is enabled.
    enabled: bool,
    /// Directory URL for the ACME provider.
    directory_url: String,
    /// Contact email for the ACME account.
    email: Option<String>,
    /// Local path where the account credentials and certs are stored.
    storage_dir: PathBuf,
    /// CIDR ranges allowed to connect to the HTTP-01 challenge server.
    /// Empty = allow all.
    allowed_cidrs: Vec<String>,
}

impl AcmeManager {
    /// Create a new ACME manager from configuration.
    pub fn new(config: &AcmeConfig) -> Self {
        Self {
            enabled: config.enabled,
            directory_url: config.directory_url.clone(),
            email: config.email.clone(),
            storage_dir: config.storage_dir.clone(),
            allowed_cidrs: config.challenge_allowed_cidrs.clone(),
        }
    }

    /// Check whether ACME is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Request a single certificate for `domain` via HTTP-01 challenge.
    ///
    /// The challenge token is served on `0.0.0.0:{challenge_port}` at
    /// `/.well-known/acme-challenge/{token}`.  The caller is responsible for
    /// ensuring that port is reachable from the Internet.
    ///
    /// On success, the certificate chain is written to
    /// `{cert_dir}/{domain}.pem` and the private key to
    /// `{cert_dir}/{domain}-key.pem`.
    pub async fn order_one(
        &self,
        domain: &str,
        email: &str,
        cert_dir: &Path,
        challenge_port: u16,
        waf: Option<WafFn>,
    ) -> anyhow::Result<()> {
        let account = self.load_or_create_account(email).await?;

        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(domain.to_string())],
            })
            .await?;

        let authorizations = order.authorizations().await?;

        // Find HTTP-01 challenges and populate the token map for the challenge server.
        let mut challenge_urls = Vec::new();
        let token_map: Arc<DashMap<String, String>> = Arc::new(DashMap::new());

        for auth in &authorizations {
            let challenge = auth
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("no HTTP-01 challenge available for {domain}"))?;

            let key_auth = order.key_authorization(challenge);
            token_map.insert(challenge.token.clone(), key_auth.as_str().to_string());
            challenge_urls.push(challenge.url.clone());
        }

        // Build IP allowlist for the challenge server.
        let ip_matcher = if self.allowed_cidrs.is_empty() {
            None
        } else {
            Some(
                IpMatcher::new(&self.allowed_cidrs)
                    .map_err(|e| anyhow::anyhow!("invalid ACME allowed CIDR: {e}"))?,
            )
        };

        // Spin up the temporary HTTP challenge server.
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let tm = token_map.clone();
        let server_handle = tokio::spawn(async move {
            challenge_server(tm, challenge_port, shutdown_rx, ip_matcher, waf).await
        });

        // Small grace period for the server to start.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Notify ACME server that challenges are ready.
        for url in &challenge_urls {
            order.set_challenge_ready(url).await?;
        }

        // Poll until order is Ready (timeout: 60s).
        let ready = wait_for_status(&mut order, OrderStatus::Ready, 60).await;

        // Always shut down the challenge server.
        let _ = shutdown_tx.send(());
        let _ = server_handle.await;

        ready?;

        // Generate ECDSA-P256 key pair and CSR with rcgen.
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let params = CertificateParams::new(vec![domain.to_string()])?;
        let csr = params.serialize_request(&key_pair)?;

        order.finalize(csr.der()).await?;

        // Poll until cert is available (timeout: 60s).
        wait_for_status(&mut order, OrderStatus::Valid, 60).await?;

        let cert_pem = order
            .certificate()
            .await?
            .ok_or_else(|| anyhow::anyhow!("ACME order succeeded but certificate is missing"))?;

        // Write certificate chain and private key to disk.
        std::fs::create_dir_all(cert_dir)?;
        let safe_name = domain.replace('*', "wildcard").replace('/', "_");
        let cert_file = cert_dir.join(format!("{safe_name}.pem"));
        let key_file = cert_dir.join(format!("{safe_name}-key.pem"));
        std::fs::write(&cert_file, &cert_pem)?;
        std::fs::write(&key_file, key_pair.serialize_pem())?;

        tracing::info!(
            domain = %domain,
            cert = %cert_file.display(),
            key = %key_file.display(),
            "ACME certificate issued successfully",
        );

        Ok(())
    }

    /// Begin the certificate provisioning loop.
    pub async fn run(&self) -> CoreResult<()> {
        if !self.enabled {
            tracing::info!("ACME is disabled, skipping");
            return Ok(());
        }
        tracing::info!(
            directory_url = %self.directory_url,
            "ACME manager started; use POST /api/certs/acme to issue certificates",
        );
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    async fn load_or_create_account(&self, email: &str) -> anyhow::Result<Account> {
        std::fs::create_dir_all(&self.storage_dir)?;
        let credentials_path = self.storage_dir.join("account.json");

        if credentials_path.exists() {
            let json = std::fs::read_to_string(&credentials_path)?;
            let credentials: AccountCredentials = serde_json::from_str(&json)?;
            tracing::debug!("loaded existing ACME account from {}", credentials_path.display());
            return Ok(Account::from_credentials(credentials).await?);
        }

        tracing::info!(%email, directory_url = %self.directory_url, "creating new ACME account");
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{email}")],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            &self.directory_url,
            None,
        )
        .await?;

        let creds_json = serde_json::to_string_pretty(&credentials)?;
        std::fs::write(&credentials_path, creds_json)?;
        tracing::info!("ACME account created and saved to {}", credentials_path.display());

        Ok(account)
    }
}

// ---------------------------------------------------------------------------
// HTTP-01 Challenge Server
// ---------------------------------------------------------------------------

/// Minimal HTTP/1.1 server that serves ACME HTTP-01 challenge tokens.
///
/// Shuts down when `shutdown_rx` fires.  This server intentionally handles
/// only the one path ACME needs; all other requests receive 404.
async fn challenge_server(
    token_map: Arc<DashMap<String, String>>,
    port: u16,
    shutdown_rx: oneshot::Receiver<()>,
    allowed: Option<IpMatcher>,
    waf: Option<WafFn>,
) {
    let addr: std::net::SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(port, error = %e, "failed to bind ACME challenge server");
            return;
        }
    };

    tracing::info!(port, "ACME HTTP-01 challenge server listening");

    let mut shutdown = std::pin::pin!(shutdown_rx);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            result = listener.accept() => {
                if let Ok((stream, peer)) = result {
                    if let Some(ref matcher) = allowed {
                        if !matcher.matches(peer.ip()) {
                            tracing::warn!(
                                peer = %peer,
                                "ACME challenge server: connection refused (not a Let's Encrypt IP)",
                            );
                            continue;
                        }
                    }
                    let tm = token_map.clone();
                    let waf = waf.clone();
                    tokio::spawn(async move { serve_challenge(stream, tm, peer, waf).await });
                }
            }
        }
    }
}

async fn serve_challenge(
    stream: tokio::net::TcpStream,
    token_map: Arc<DashMap<String, String>>,
    peer: std::net::SocketAddr,
    waf: Option<WafFn>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut request_line = String::new();

    if reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // "GET /path HTTP/1.1\r\n"
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = if parts.len() >= 1 { parts[0] } else { "" };
    let path = if parts.len() >= 2 { parts[1] } else { "" };

    // Read HTTP headers until the blank line.
    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.is_err() {
            return;
        }
        let trimmed = line.trim_end_matches("\r\n").trim_end_matches('\n');
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_lowercase(), value.trim().to_string());
        }
    }

    // WAF inspection — block if the engine says so.
    if let Some(ref waf_fn) = waf {
        if waf_fn(method, path, peer.ip(), &headers) {
            tracing::warn!(peer = %peer, %path, "ACME challenge request blocked by WAF");
            let _ = write_half.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
            return;
        }
    }

    let prefix = "/.well-known/acme-challenge/";
    let response = if let Some(token) = path.strip_prefix(prefix) {
        if let Some(key_auth) = token_map.get(token) {
            let body = key_auth.value().clone();
            tracing::info!(peer = %peer, %path, "ACME challenge token served (200)");
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
        } else {
            tracing::warn!(peer = %peer, %path, "ACME challenge token not found (404)");
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
        }
    } else {
        tracing::debug!(peer = %peer, %path, "ACME challenge server: unexpected path (404)");
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
    };

    let _ = write_half.write_all(response.as_bytes()).await;
}

// ---------------------------------------------------------------------------
// Order polling
// ---------------------------------------------------------------------------

async fn wait_for_status(
    order: &mut instant_acme::Order,
    target: OrderStatus,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        let state = order.refresh().await?;
        if state.status == target {
            return Ok(());
        }
        if state.status == OrderStatus::Invalid {
            anyhow::bail!("ACME order transitioned to Invalid: {:?}", state.error);
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timeout waiting for ACME order status {:?} (current: {:?})",
                target,
                state.status,
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
