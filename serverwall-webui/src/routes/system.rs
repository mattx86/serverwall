use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_rustls::TlsAcceptor;

use crate::state::AppState;
use crate::tls;

#[derive(Deserialize)]
pub struct SetWebuiCertRequest {
    pub cert_name: String,
}

/// POST /api/system/webui-cert — hot-swap the TLS certificate used by the WebUI.
///
/// Locates `{cert_name}.pem` and `{cert_name}-key.pem` in the configured cert_dir,
/// loads a new rustls config, swaps the live TlsAcceptor, and persists the paths to
/// serverwall.toml so the change survives a restart.
pub async fn set_webui_cert(
    State(state): State<AppState>,
    Json(req): Json<SetWebuiCertRequest>,
) -> (StatusCode, Json<Value>) {
    let cert_name = sanitize_name(&req.cert_name);
    if cert_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid cert_name"})),
        );
    }

    let cert_path;
    let key_path;
    {
        let config = state.config.load();
        let cert_dir = &config.global.cert_dir;
        cert_path = cert_dir.join(format!("{}.pem", cert_name));
        key_path = cert_dir.join(format!("{}-key.pem", cert_name));
    }

    if !cert_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "certificate file not found"})),
        );
    }
    if !key_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "private key file not found"})),
        );
    }

    // Load and validate the new TLS config before touching anything.
    let new_config = match tls::load_tls_config(&cert_path, &key_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("failed to load TLS config: {}", e)})),
            )
        }
    };

    // Swap the live acceptor (no-op if running in plain-HTTP mode).
    if let Some(lock) = &state.tls_acceptor {
        *lock.write().await = TlsAcceptor::from(Arc::new(new_config));
        tracing::info!(cert = %cert_path.display(), "webui TLS certificate hot-swapped");
    }

    // Persist the new paths to serverwall.toml and update in-memory config.
    if let Err(e) = persist_webui_cert(&state, &cert_path, &key_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("TLS swapped live but failed to persist: {}", e)})),
        );
    }

    (StatusCode::OK, Json(json!({"applied": true})))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn sanitize_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

fn persist_webui_cert(
    state: &AppState,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<()> {
    // Clone current in-memory config and apply the change.
    let mut cfg = (**state.config.load()).clone();
    cfg.webui.tls_cert = Some(cert_path.to_path_buf());
    cfg.webui.tls_key  = Some(key_path.to_path_buf());

    // Write to disk.
    let serialized = toml::to_string_pretty(&cfg)?;
    std::fs::write(&state.config_path, &serialized)?;

    // Update in-memory state directly — no full reload needed.
    state.config.store(Arc::new(cfg));
    Ok(())
}
