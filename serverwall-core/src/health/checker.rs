use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::config::schema::{BackendPoolConfig, HealthCheckType};
use crate::types::Backend;

/// Periodically checks backend health using configurable check types.
pub struct HealthChecker {
    backends: Vec<Arc<Backend>>,
    check_type: HealthCheckType,
    interval: Duration,
    timeout: Duration,
    check_path: Option<String>,
    expected_status: u16,
    tls: bool,
    ignore_cert: bool,
    method: String,
}

/// A `ServerCertVerifier` that accepts any certificate without verification.
#[derive(Debug)]
struct IgnoreCertVerifier;

impl rustls::client::danger::ServerCertVerifier for IgnoreCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Parse a simple duration string like "10s", "30s", "500ms" into a `Duration`.
/// Supports suffixes: "ms" for milliseconds, "s" for seconds, "m" for minutes.
/// Falls back to seconds if no suffix is recognized.
pub fn parse_duration(s: &str) -> Duration {
    let s = s.trim();
    if let Some(num) = s.strip_suffix("ms") {
        Duration::from_millis(num.parse().unwrap_or(10_000))
    } else if let Some(num) = s.strip_suffix('s') {
        Duration::from_secs(num.parse().unwrap_or(10))
    } else if let Some(num) = s.strip_suffix('m') {
        Duration::from_secs(num.parse::<u64>().unwrap_or(1) * 60)
    } else {
        Duration::from_secs(s.parse().unwrap_or(10))
    }
}

impl HealthChecker {
    /// Create a new health checker from a list of backends and pool configuration.
    pub fn new(backends: Vec<Arc<Backend>>, config: &BackendPoolConfig) -> Self {
        Self {
            backends,
            check_type: config.health_check_type,
            interval: parse_duration(&config.health_check_interval),
            timeout: parse_duration(&config.health_check_timeout),
            check_path: config.health_check_path.clone(),
            expected_status: config.health_check_expect,
            tls: config.health_check_tls,
            ignore_cert: config.health_check_ignore_cert,
            method: config.health_check_method.clone(),
        }
    }

    /// Establish a TLS connection to `addr`, optionally skipping cert verification.
    async fn tls_connect(
        addr: std::net::SocketAddr,
        ignore_cert: bool,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await?;

        let config = if ignore_cert {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(IgnoreCertVerifier))
                .with_no_client_auth()
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                root_store.add(cert).ok();
            }
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::IpAddress(addr.ip().into());
        connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    /// Run the health-checking loop until a shutdown signal is received.
    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        tracing::info!(
            check_type = ?self.check_type,
            interval_secs = self.interval.as_secs(),
            timeout_secs = self.timeout.as_secs(),
            backend_count = self.backends.len(),
            "health checker started",
        );

        let mut ticker = tokio::time::interval(self.interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    for backend in &self.backends {
                        let healthy = self.check_backend(backend).await;
                        let previous = backend.healthy.swap(healthy, Ordering::Relaxed);

                        if previous != healthy {
                            if healthy {
                                tracing::info!(
                                    backend = %backend.id,
                                    address = %backend.address,
                                    "backend became healthy",
                                );
                            } else {
                                tracing::warn!(
                                    backend = %backend.id,
                                    address = %backend.address,
                                    "backend became unhealthy",
                                );
                            }
                        } else {
                            tracing::trace!(
                                backend = %backend.id,
                                address = %backend.address,
                                healthy,
                                "health check completed",
                            );
                        }
                    }
                }
                result = shutdown.changed() => {
                    if result.is_ok() && *shutdown.borrow() {
                        tracing::info!("health checker shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Perform a single health check against one backend.
    async fn check_backend(&self, backend: &Backend) -> bool {
        match self.check_type {
            HealthCheckType::Tcp     => self.check_tcp(backend).await,
            HealthCheckType::Http    => self.check_http(backend).await,
            HealthCheckType::Smtp    => self.check_smtp(backend).await,
            HealthCheckType::Imap    => self.check_imap(backend).await,
            HealthCheckType::Stratum => self.check_stratum(backend).await,
        }
    }

    /// TCP check: success if we can establish a connection within the timeout.
    async fn check_tcp(&self, backend: &Backend) -> bool {
        match timeout(self.timeout, TcpStream::connect(backend.address)).await {
            Ok(Ok(_stream)) => true,
            Ok(Err(e)) => {
                tracing::debug!(
                    backend = %backend.id,
                    error = %e,
                    "TCP health check: connection failed",
                );
                false
            }
            Err(_) => {
                tracing::debug!(
                    backend = %backend.id,
                    "TCP health check: connection timed out",
                );
                false
            }
        }
    }

    /// HTTP/HTTPS check: connect, send request, verify expected status code.
    async fn check_http(&self, backend: &Backend) -> bool {
        let path = self.check_path.as_deref().unwrap_or("/");
        let host = backend.address.ip().to_string();
        let method = self.method.as_str();
        let addr = backend.address;
        let ignore_cert = self.ignore_cert;
        let use_tls = self.tls;
        let expected = self.expected_status;

        let result = timeout(self.timeout, async move {
            let request = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                method, path, host
            );

            let parse_status = |buf: &[u8]| -> bool {
                let response = String::from_utf8_lossy(buf);
                if let Some(status_line) = response.lines().next() {
                    let parts: Vec<&str> = status_line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(code) = parts[1].parse::<u16>() {
                            return code == expected;
                        }
                    }
                }
                false
            };

            if use_tls {
                let mut stream = Self::tls_connect(addr, ignore_cert).await?;
                stream.write_all(request.as_bytes()).await?;
                let mut buf = vec![0u8; 1024];
                let n = stream.read(&mut buf).await?;
                Ok::<bool, std::io::Error>(parse_status(&buf[..n]))
            } else {
                let mut stream = TcpStream::connect(addr).await?;
                stream.write_all(request.as_bytes()).await?;
                let mut buf = vec![0u8; 1024];
                let n = stream.read(&mut buf).await?;
                Ok::<bool, std::io::Error>(parse_status(&buf[..n]))
            }
        })
        .await;

        match result {
            Ok(Ok(healthy)) => healthy,
            Ok(Err(e)) => {
                tracing::debug!(
                    backend = %backend.id,
                    tls = use_tls,
                    error = %e,
                    "HTTP health check failed",
                );
                false
            }
            Err(_) => {
                tracing::debug!(
                    backend = %backend.id,
                    tls = use_tls,
                    "HTTP health check timed out",
                );
                false
            }
        }
    }

    /// SMTP/SMTPS check: connect (optionally via TLS), read banner, success if it starts with "220".
    async fn check_smtp(&self, backend: &Backend) -> bool {
        let addr = backend.address;
        let ignore_cert = self.ignore_cert;
        let use_tls = self.tls;

        let result = timeout(self.timeout, async move {
            let mut buf = vec![0u8; 512];
            let n = if use_tls {
                let mut stream = Self::tls_connect(addr, ignore_cert).await?;
                stream.read(&mut buf).await?
            } else {
                let mut stream = TcpStream::connect(addr).await?;
                stream.read(&mut buf).await?
            };
            let banner = String::from_utf8_lossy(&buf[..n]);
            Ok::<bool, std::io::Error>(banner.starts_with("220"))
        })
        .await;

        match result {
            Ok(Ok(healthy)) => healthy,
            Ok(Err(e)) => {
                tracing::debug!(
                    backend = %backend.id,
                    tls = use_tls,
                    error = %e,
                    "SMTP health check failed",
                );
                false
            }
            Err(_) => {
                tracing::debug!(
                    backend = %backend.id,
                    tls = use_tls,
                    "SMTP health check timed out",
                );
                false
            }
        }
    }

    /// Stratum check: connect, send `mining.subscribe`, verify a successful JSON-RPC response.
    async fn check_stratum(&self, backend: &Backend) -> bool {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use crate::proto::stratum;

        let addr = backend.address;
        let to = self.timeout;

        let result = timeout(to, async move {
            let stream = TcpStream::connect(addr).await?;
            let mut buf = BufReader::new(stream);
            let req = b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"serverwall-healthcheck/1.0\",null]}\n";
            buf.get_mut().write_all(req).await?;
            let mut line = String::new();
            let n = buf.read_line(&mut line).await?;
            if n == 0 {
                return Ok::<bool, std::io::Error>(false);
            }
            let ok = stratum::parse_line(&line)
                .map(|msg| stratum::is_success_response(&msg, 1))
                .unwrap_or(false);
            Ok::<bool, std::io::Error>(ok)
        })
        .await;

        match result {
            Ok(Ok(healthy)) => healthy,
            Ok(Err(e)) => {
                tracing::debug!(
                    backend = %backend.id,
                    error = %e,
                    "Stratum health check failed",
                );
                false
            }
            Err(_) => {
                tracing::debug!(
                    backend = %backend.id,
                    "Stratum health check timed out",
                );
                false
            }
        }
    }

    /// IMAP/IMAPS check: connect (optionally via TLS), read banner, success if it starts with "* OK".
    async fn check_imap(&self, backend: &Backend) -> bool {
        let addr = backend.address;
        let ignore_cert = self.ignore_cert;
        let use_tls = self.tls;

        let result = timeout(self.timeout, async move {
            let mut buf = vec![0u8; 512];
            let n = if use_tls {
                let mut stream = Self::tls_connect(addr, ignore_cert).await?;
                stream.read(&mut buf).await?
            } else {
                let mut stream = TcpStream::connect(addr).await?;
                stream.read(&mut buf).await?
            };
            let banner = String::from_utf8_lossy(&buf[..n]);
            Ok::<bool, std::io::Error>(banner.starts_with("* OK"))
        })
        .await;

        match result {
            Ok(Ok(healthy)) => healthy,
            Ok(Err(e)) => {
                tracing::debug!(
                    backend = %backend.id,
                    tls = use_tls,
                    error = %e,
                    "IMAP health check failed",
                );
                false
            }
            Err(_) => {
                tracing::debug!(
                    backend = %backend.id,
                    tls = use_tls,
                    "IMAP health check timed out",
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("10s"), Duration::from_secs(10));
        assert_eq!(parse_duration("30s"), Duration::from_secs(30));
        assert_eq!(parse_duration("1s"), Duration::from_secs(1));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("5m"), Duration::from_secs(300));
        assert_eq!(parse_duration("1m"), Duration::from_secs(60));
    }

    #[test]
    fn test_parse_duration_milliseconds() {
        assert_eq!(parse_duration("500ms"), Duration::from_millis(500));
        assert_eq!(parse_duration("100ms"), Duration::from_millis(100));
    }

    #[test]
    fn test_parse_duration_plain_number() {
        assert_eq!(parse_duration("10"), Duration::from_secs(10));
    }

    #[test]
    fn test_parse_duration_with_whitespace() {
        assert_eq!(parse_duration("  10s  "), Duration::from_secs(10));
    }

    #[test]
    fn test_parse_duration_invalid_falls_back() {
        assert_eq!(parse_duration("abc"), Duration::from_secs(10));
        assert_eq!(parse_duration("abcs"), Duration::from_secs(10));
    }
}
