use std::path::Path;

use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Load a rustls ServerConfig from PEM cert and key files.
pub fn load_tls_config(cert_path: &Path, key_path: &Path) -> anyhow::Result<ServerConfig> {
    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("failed to open cert {}: {}", cert_path.display(), e))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| anyhow::anyhow!("failed to open key {}: {}", key_path.display(), e))?;

    let mut cert_reader = std::io::BufReader::new(cert_file);
    let mut key_reader = std::io::BufReader::new(key_file);

    let cert_chain: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse cert: {}", e))?;

    let key: PrivateKeyDer<'static> = private_key(&mut key_reader)
        .map_err(|e| anyhow::anyhow!("failed to parse private key: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?;

    Ok(config)
}

