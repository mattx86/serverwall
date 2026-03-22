use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::schema::DkimDomainConfig;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// GET /api/dkim — list all configured DKIM signing domains.
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let domains: Vec<Value> = config.relay.dkim.domains.iter().map(|d| json!({
        "domain":    d.domain,
        "selector":  d.selector,
        "key_file":  d.key_file.display().to_string(),
        "algorithm": d.algorithm,
    })).collect();
    Json(json!({ "domains": domains }))
}

/// POST /api/dkim/generate — generate a 2048-bit RSA DKIM key pair and register it.
///
/// Request body: `{ "domain": "example.com", "selector": "mail", "key_dir": "/opt/serverwall/etc/dkim" }`
pub async fn generate(
    State(state): State<AppState>,
    Json(req): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let domain = match req.get("domain").and_then(|v| v.as_str()) {
        Some(d) => d.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "domain is required"}))),
    };
    let selector = req.get("selector")
        .and_then(|v| v.as_str())
        .unwrap_or("mail")
        .to_string();
    let key_dir = req.get("key_dir")
        .and_then(|v| v.as_str())
        .unwrap_or("/opt/serverwall/etc/dkim")
        .to_string();

    let config_path = state.config_path.clone();

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<(String, String)> {
        let key_dir = PathBuf::from(key_dir);
        std::fs::create_dir_all(&key_dir)?;
        let key_file = key_dir.join(format!("{}_{}.pem", domain, selector));

        // Generate RSA 2048-bit private key
        let rsa = openssl::rsa::Rsa::generate(2048)?;
        let pkey = openssl::pkey::PKey::from_rsa(rsa.clone())?;
        let pem = pkey.private_key_to_pem_pkcs8()?;
        std::fs::write(&key_file, &pem)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))?;
        }

        // Build DNS TXT record value
        let pub_der = rsa.public_key_to_der()?;
        let pub_b64 = openssl::base64::encode_block(&pub_der);
        let dns_record = format!(
            "{}._domainkey.{}  IN TXT  \"v=DKIM1; k=rsa; p={}\"",
            selector, domain, pub_b64
        );

        // Register in config
        let entry = DkimDomainConfig {
            domain: domain.clone(),
            selector,
            key_file: key_file.clone(),
            algorithm: "rsa-sha256".to_string(),
        };
        editor::add_dkim_domain(&config_path, entry)?;

        Ok((key_file.display().to_string(), dns_record))
    }).await;

    match result {
        Ok(Ok((key_file, dns_record))) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({
                "created": true,
                "key_file": key_file,
                "dns_record": dns_record,
            })))
        }
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

/// GET /api/dkim/{domain}/dns — return the DNS TXT record for a configured domain.
pub async fn dns_record(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    let entry = match config.relay.dkim.domains.iter().find(|d| d.domain == domain) {
        Some(e) => e.clone(),
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "DKIM domain not found"}))),
    };

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let pem = std::fs::read(&entry.key_file)?;
        let pkey = openssl::pkey::PKey::private_key_from_pem(&pem)?;
        let rsa = pkey.rsa()?;
        let pub_der = rsa.public_key_to_der()?;
        let pub_b64 = openssl::base64::encode_block(&pub_der);
        Ok(format!(
            "{}._domainkey.{}  IN TXT  \"v=DKIM1; k=rsa; p={}\"",
            entry.selector, entry.domain, pub_b64
        ))
    }).await;

    match result {
        Ok(Ok(record)) => (StatusCode::OK, Json(json!({ "dns_record": record }))),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

/// DELETE /api/dkim/{domain} — remove a DKIM domain from config (key file is not deleted).
pub async fn delete(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_dkim_domain(&state.config_path, &domain) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"deleted": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}
