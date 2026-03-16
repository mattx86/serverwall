use std::net::IpAddr;
use thiserror::Error;

use crate::types::{BackendId, FrontendId, PoolId};

#[derive(Debug, Error)]
pub enum ServerWallError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("failed to load configuration file: {path}")]
    ConfigLoad {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("certificate not found for domain: {domain}")]
    CertNotFound { domain: String },

    #[error("ACME error: {0}")]
    Acme(String),

    #[error("backend not found: {0}")]
    BackendNotFound(BackendId),

    #[error("frontend not found: {0}")]
    FrontendNotFound(FrontendId),

    #[error("pool not found: {0}")]
    PoolNotFound(PoolId),

    #[error("no healthy backends available in pool {0}")]
    NoHealthyBackends(PoolId),

    #[error("access denied for {ip}")]
    AccessDenied { ip: IpAddr },

    #[error("health check failed for backend {backend_id}: {reason}")]
    HealthCheckFailed {
        backend_id: BackendId,
        reason: String,
    },

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("WAF blocked request: {reason} (rule: {rule_id})")]
    WafBlocked { rule_id: String, reason: String },

    #[error("rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("spam rejected: score {score}% exceeds threshold {threshold}%")]
    SpamRejected { score: u8, threshold: u8 },

    #[error("virus detected: {virus_name} (scanner: {scanner})")]
    VirusDetected {
        virus_name: String,
        scanner: String,
    },

    #[error("relay denied: {reason}")]
    RelayDenied { reason: String },

    #[error("queue error: {0}")]
    Queue(String),

    #[error("DKIM signing error: {0}")]
    DkimSign(String),

    #[error("DNS resolution error: {0}")]
    DnsError(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, ServerWallError>;
