use std::sync::Arc;

use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;

use crate::error::Result;
use crate::tls::CertStore;

/// Build a `TlsAcceptor` backed by a `CertStore` for SNI-based certificate
/// resolution.
///
/// The `CertStore` must already have certificates loaded and registered before
/// calling this function. It is wrapped in an `Arc` so it can be shared with
/// the resulting `TlsAcceptor`.
pub fn build_tls_acceptor(cert_store: Arc<CertStore>) -> Result<TlsAcceptor> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_store);

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build a `TlsConnector` for outbound connections to backends.
///
/// When `verify` is `true`, the connector validates the server certificate
/// against the system root store. When `false`, certificate
/// verification is skipped (useful for self-signed backend certs in trusted
/// networks).
pub fn build_tls_connector(verify: bool) -> Result<TlsConnector> {
    let config = if verify {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            root_store.add(cert).ok();
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

// ---------------------------------------------------------------------------
// No-verification implementation for skip-verify mode
// ---------------------------------------------------------------------------

/// A `ServerCertVerifier` that accepts any certificate without verification.
///
/// **WARNING**: This disables all TLS security guarantees and should only be
/// used for backend connections in trusted networks where the backend uses a
/// self-signed certificate.
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
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
