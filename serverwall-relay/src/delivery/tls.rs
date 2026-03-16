use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use serverwall_core::config::schema::RelayTlsConfig;

/// Manages TLS configuration for outbound SMTP connections (opportunistic STARTTLS).
pub struct OutboundTls {
    connector: TlsConnector,
    opportunistic: bool,
}

impl OutboundTls {
    /// Build from relay TLS config.
    pub fn new(config: &RelayTlsConfig) -> Result<Self> {
        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(Self::root_store())
            .with_no_client_auth();

        if !config.verify_certificates {
            // For opportunistic TLS we may want to skip verification
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerify));
        }

        Ok(Self {
            connector: TlsConnector::from(Arc::new(tls_config)),
            opportunistic: config.opportunistic,
        })
    }

    /// Whether we should attempt STARTTLS at all.
    pub fn is_enabled(&self) -> bool {
        self.opportunistic
    }

    /// Upgrade a TCP stream to TLS.  Returns `Ok(tls_stream)` on success.
    /// The caller should catch errors and fall back to plaintext when
    /// `opportunistic` is true.
    pub async fn upgrade(&self, stream: TcpStream, hostname: &str) -> Result<TlsStream<TcpStream>> {
        let server_name = ServerName::try_from(hostname.to_string())
            .context("invalid server name for TLS")?;
        let tls_stream = self
            .connector
            .connect(server_name, stream)
            .await
            .context("TLS handshake failed")?;
        Ok(tls_stream)
    }

    fn root_store() -> rustls::RootCertStore {
        let mut store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            store.add(cert).ok();
        }
        store
    }
}

/// Certificate verifier that accepts anything (for opportunistic mode
/// without verification).
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
