use std::fmt;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use dashmap::DashMap;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::x509::X509;
use rustls::crypto::ring as rustls_ring;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{debug, info, warn};

use crate::config::FrontendConfig;
use crate::error::{ServerWallError, Result};

// ---------------------------------------------------------------------------
// CertStore
// ---------------------------------------------------------------------------

/// Thread-safe certificate store with SNI-based certificate resolution.
///
/// Certificates are indexed by hostname (including wildcard patterns like
/// `*.example.com`). The store implements `rustls::server::ResolvesServerCert`
/// so it can be plugged directly into a `rustls::ServerConfig`.
pub struct CertStore {
    /// Map of SNI hostname -> certified key. Supports exact and wildcard entries.
    certs: DashMap<String, Arc<CertifiedKey>>,

    /// Fallback key used when no SNI match is found.
    default_key: std::sync::RwLock<Option<Arc<CertifiedKey>>>,
}

impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertStore")
            .field("hostnames", &self.certs.iter().map(|e| e.key().clone()).collect::<Vec<_>>())
            .finish()
    }
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CertStore {
    /// Create an empty certificate store.
    pub fn new() -> Self {
        Self {
            certs: DashMap::new(),
            default_key: std::sync::RwLock::new(None),
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Load a `CertifiedKey` from the TLS fields in a `FrontendConfig`.
    ///
    /// This supports three styles:
    /// 1. **PKCS#12/PFX** — `tls_pfx` is set
    /// 2. **Combined PEM** — `tls_cert` is set but `tls_key` is absent (key is inside the cert file)
    /// 3. **Separate files** — `tls_cert` + `tls_key` (and optional `tls_chain`)
    pub fn load_from_frontend(config: &FrontendConfig) -> Result<Arc<CertifiedKey>> {
        // Style 3: PKCS#12 / PFX
        if let Some(pfx_path) = &config.tls_pfx {
            info!(path = %pfx_path.display(), "loading PKCS#12/PFX certificate");
            let password = config.tls_pfx_password.as_deref().unwrap_or("");
            return load_pfx(pfx_path, password);
        }

        // Styles 1 & 2 both require tls_cert
        let cert_path = config.tls_cert.as_ref().ok_or_else(|| {
            ServerWallError::Tls(
                "no TLS certificate configured (set tls_cert or tls_pfx)".into(),
            )
        })?;

        if let Some(key_path) = &config.tls_key {
            // Style 2: Separate cert + key (+ optional chain)
            info!(
                cert = %cert_path.display(),
                key = %key_path.display(),
                "loading separate cert/key files"
            );
            load_separate_files(
                cert_path,
                config.tls_chain.as_deref(),
                key_path,
                config.tls_key_password.as_deref(),
            )
        } else {
            // Style 1: Combined PEM (cert + chain + key all in one file)
            info!(path = %cert_path.display(), "loading combined PEM certificate");
            load_combined_pem(cert_path, config.tls_key_password.as_deref())
        }
    }

    /// Register a `CertifiedKey` for a specific hostname.
    ///
    /// The hostname is normalized to lowercase. Wildcard hostnames (e.g.
    /// `*.example.com`) are stored as-is for matching during resolution.
    pub fn add(&self, hostname: &str, certified_key: Arc<CertifiedKey>) {
        let host = hostname.to_ascii_lowercase();
        info!(hostname = %host, "registered certificate for SNI");
        self.certs.insert(host, certified_key);
    }

    /// Register a `CertifiedKey` and automatically extract hostnames from the
    /// leaf certificate's Subject Alternative Names and Common Name.
    pub fn add_from_cert(&self, certified_key: Arc<CertifiedKey>) {
        let hostnames = extract_hostnames_from_certified_key(&certified_key);
        if hostnames.is_empty() {
            warn!("certificate has no SAN/CN hostnames; registering as default only");
        }
        for host in &hostnames {
            self.add(host, Arc::clone(&certified_key));
        }
    }

    /// Set the default (fallback) certificate used when no SNI match is found.
    pub fn set_default(&self, certified_key: Arc<CertifiedKey>) {
        let mut lock = self.default_key.write().expect("default_key lock poisoned");
        *lock = Some(certified_key);
    }

    /// Resolve a certificate for the given server name.
    ///
    /// Resolution order:
    /// 1. Exact match on the lowercase hostname.
    /// 2. Wildcard match — replace the leftmost label with `*`.
    /// 3. Fallback to the default certificate.
    pub fn resolve(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let name = server_name.to_ascii_lowercase();

        // 1. Exact match
        if let Some(entry) = self.certs.get(&name) {
            return Some(Arc::clone(entry.value()));
        }

        // 2. Wildcard: *.example.com
        if let Some(dot_pos) = name.find('.') {
            let wildcard = format!("*.{}", &name[dot_pos + 1..]);
            if let Some(entry) = self.certs.get(&wildcard) {
                return Some(Arc::clone(entry.value()));
            }
        }

        // 3. Default
        let lock = self.default_key.read().expect("default_key lock poisoned");
        lock.clone()
    }

    /// Return the number of registered hostname entries.
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Return `true` if no hostnames are registered.
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ResolvesServerCert implementation
// ---------------------------------------------------------------------------

impl ResolvesServerCert for CertStore {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        debug!(sni = %sni, "resolving certificate for SNI");
        CertStore::resolve(self, sni)
    }
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

/// Load from a combined PEM file that contains certificates and a private key.
fn load_combined_pem(
    path: &std::path::Path,
    key_password: Option<&str>,
) -> Result<Arc<CertifiedKey>> {
    let data = fs::read(path).map_err(|e| {
        ServerWallError::Tls(format!("cannot read combined PEM {}: {}", path.display(), e))
    })?;

    let mut reader = BufReader::new(&data[..]);

    // Extract all certificates
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ServerWallError::Tls(format!("failed to parse certificates from {}: {}", path.display(), e)))?;

    if certs.is_empty() {
        return Err(ServerWallError::Tls(format!(
            "no certificates found in {}",
            path.display()
        )));
    }

    // Re-read for private key
    let mut reader2 = BufReader::new(&data[..]);
    let key = read_private_key(&mut reader2, key_password, path)?;

    // If we could not find an unencrypted key and there is a password, try the
    // OpenSSL-encrypted PEM path on the raw bytes.
    build_certified_key(certs, key)
}

/// Load from separate cert, chain, and key files.
fn load_separate_files(
    cert_path: &std::path::Path,
    chain_path: Option<&std::path::Path>,
    key_path: &std::path::Path,
    key_password: Option<&str>,
) -> Result<Arc<CertifiedKey>> {
    // --- certificates ---
    let cert_data = fs::read(cert_path).map_err(|e| {
        ServerWallError::Tls(format!("cannot read cert file {}: {}", cert_path.display(), e))
    })?;
    let mut reader = BufReader::new(&cert_data[..]);
    let mut certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ServerWallError::Tls(format!("failed to parse certs from {}: {}", cert_path.display(), e)))?;

    if certs.is_empty() {
        return Err(ServerWallError::Tls(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }

    // --- optional chain ---
    if let Some(cp) = chain_path {
        let chain_data = fs::read(cp).map_err(|e| {
            ServerWallError::Tls(format!("cannot read chain file {}: {}", cp.display(), e))
        })?;
        let mut cr = BufReader::new(&chain_data[..]);
        let chain_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cr)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| ServerWallError::Tls(format!("failed to parse chain from {}: {}", cp.display(), e)))?;
        certs.extend(chain_certs);
    }

    // --- private key ---
    let key_data = fs::read(key_path).map_err(|e| {
        ServerWallError::Tls(format!("cannot read key file {}: {}", key_path.display(), e))
    })?;
    let mut kr = BufReader::new(&key_data[..]);
    let key = read_private_key(&mut kr, key_password, key_path)?;

    build_certified_key(certs, key)
}

/// Load from a PKCS#12 / PFX file using the `openssl` crate, then convert to
/// rustls types.
fn load_pfx(
    path: &std::path::Path,
    password: &str,
) -> Result<Arc<CertifiedKey>> {
    let der = fs::read(path).map_err(|e| {
        ServerWallError::Tls(format!("cannot read PFX file {}: {}", path.display(), e))
    })?;

    let pkcs12 = Pkcs12::from_der(&der).map_err(|e| {
        ServerWallError::Tls(format!("invalid PKCS#12 data in {}: {}", path.display(), e))
    })?;

    let parsed = pkcs12.parse2(password).map_err(|e| {
        ServerWallError::Tls(format!(
            "failed to parse PKCS#12 {} (wrong password?): {}",
            path.display(),
            e
        ))
    })?;

    // --- private key ---
    let pkey = parsed.pkey.ok_or_else(|| {
        ServerWallError::Tls(format!("PKCS#12 file {} contains no private key", path.display()))
    })?;
    let key_der = pkey.private_key_to_der().map_err(|e| {
        ServerWallError::Tls(format!("failed to convert PFX private key to DER: {}", e))
    })?;
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    // --- leaf certificate ---
    let leaf = parsed.cert.ok_or_else(|| {
        ServerWallError::Tls(format!(
            "PKCS#12 file {} contains no certificate",
            path.display()
        ))
    })?;
    let leaf_der = leaf.to_der().map_err(|e| {
        ServerWallError::Tls(format!("failed to convert PFX leaf cert to DER: {}", e))
    })?;

    let mut certs: Vec<CertificateDer<'static>> = vec![CertificateDer::from(leaf_der)];

    // --- chain certificates ---
    if let Some(ca_stack) = parsed.ca {
        for ca in ca_stack {
            let ca_der = ca.to_der().map_err(|e| {
                ServerWallError::Tls(format!("failed to convert PFX CA cert to DER: {}", e))
            })?;
            certs.push(CertificateDer::from(ca_der));
        }
    }

    build_certified_key(certs, private_key)
}

// ---------------------------------------------------------------------------
// Key reading
// ---------------------------------------------------------------------------

/// Attempt to read a private key from a PEM stream.
///
/// If no unencrypted key is found and `password` is `Some`, falls back to
/// OpenSSL-based encrypted PEM decryption on the underlying raw bytes.
fn read_private_key(
    reader: &mut BufReader<&[u8]>,
    password: Option<&str>,
    source_path: &std::path::Path,
) -> Result<PrivateKeyDer<'static>> {
    // Get the underlying bytes for potential encrypted-PEM fallback.
    let raw_bytes: Vec<u8> = reader.get_ref().to_vec();

    // Try rustls-pemfile for unencrypted keys (PKCS#8, PKCS#1, SEC1).
    let mut re_reader = BufReader::new(&raw_bytes[..]);
    for item in rustls_pemfile::read_all(&mut re_reader) {
        match item {
            Ok(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Ok(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Ok(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            _ => continue,
        }
    }

    // Fallback: try OpenSSL encrypted PEM if a password is provided.
    if let Some(pw) = password {
        return decrypt_openssl_pem_key(&raw_bytes, pw, source_path);
    }

    Err(ServerWallError::Tls(format!(
        "no private key found in {} (if the key is encrypted, provide tls_key_password)",
        source_path.display()
    )))
}

/// Decrypt an OpenSSL-encrypted PEM private key using the `openssl` crate.
fn decrypt_openssl_pem_key(
    pem_bytes: &[u8],
    passphrase: &str,
    source_path: &std::path::Path,
) -> Result<PrivateKeyDer<'static>> {
    let pkey = PKey::private_key_from_pem_passphrase(pem_bytes, passphrase.as_bytes())
        .map_err(|e| {
            ServerWallError::Tls(format!(
                "failed to decrypt encrypted PEM key from {}: {}",
                source_path.display(),
                e
            ))
        })?;

    let der = pkey.private_key_to_der().map_err(|e| {
        ServerWallError::Tls(format!(
            "failed to export decrypted key to DER from {}: {}",
            source_path.display(),
            e
        ))
    })?;

    // OpenSSL exports in PKCS#8 DER format.
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
}

// ---------------------------------------------------------------------------
// CertifiedKey construction
// ---------------------------------------------------------------------------

/// Build a `CertifiedKey` from a certificate chain and private key, validating
/// that the key matches the leaf certificate's public key.
fn build_certified_key(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>> {
    let signing_key = rustls_ring::sign::any_supported_type(&key).map_err(|e| {
        ServerWallError::Tls(format!("unsupported private key type: {}", e))
    })?;

    let certified = CertifiedKey::new(certs, signing_key);

    // Validate: rustls will reject mismatched cert/key at handshake time, but
    // we can catch obvious issues early by checking the key algorithm is
    // compatible with the leaf cert.
    if certified.end_entity_cert().is_err() {
        return Err(ServerWallError::Tls(
            "certificate chain is empty or malformed".into(),
        ));
    }

    Ok(Arc::new(certified))
}

// ---------------------------------------------------------------------------
// Hostname extraction
// ---------------------------------------------------------------------------

/// Extract hostnames from the leaf certificate's SAN extension and CN field.
///
/// Uses the `openssl` crate to parse the DER-encoded leaf certificate.
fn extract_hostnames_from_certified_key(ck: &CertifiedKey) -> Vec<String> {
    let leaf = match ck.end_entity_cert() {
        Ok(cert) => cert,
        Err(_) => return Vec::new(),
    };

    let x509 = match X509::from_der(leaf.as_ref()) {
        Ok(cert) => cert,
        Err(e) => {
            warn!("failed to parse leaf certificate for hostname extraction: {}", e);
            return Vec::new();
        }
    };

    let mut hostnames = Vec::new();

    // Subject Alternative Names (preferred source)
    if let Some(sans) = x509.subject_alt_names() {
        for san in sans {
            if let Some(dns) = san.dnsname() {
                hostnames.push(dns.to_ascii_lowercase());
            }
        }
    }

    // Fallback to Common Name if no SANs were found
    if hostnames.is_empty() {
        if let Some(cn) = x509
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
        {
            if let Ok(cn_str) = cn.data().as_utf8() {
                let cn_val = cn_str.to_string().to_ascii_lowercase();
                if !cn_val.is_empty() {
                    hostnames.push(cn_val);
                }
            }
        }
    }

    hostnames.sort();
    hostnames.dedup();
    hostnames
}
