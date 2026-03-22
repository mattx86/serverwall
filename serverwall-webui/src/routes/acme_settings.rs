use std::path::PathBuf;

use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use serverwall_core::config::schema::AcmeConfig;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// GET /api/settings/acme — return ACME / Let's Encrypt settings
pub async fn get(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let a = &config.acme;
    Json(json!({
        "enabled": a.enabled,
        "email": a.email,
        "directory_url": a.directory_url,
        "challenge_type": a.challenge_type,
        "storage_dir": a.storage_dir,
        "auto_renew": a.auto_renew,
        "renew_before_days": a.renew_before_days,
    }))
}

/// PUT /api/settings/acme — replace ACME settings
pub async fn update(
    State(state): State<AppState>,
    Json(acme): Json<AcmeConfig>,
) -> (StatusCode, Json<Value>) {
    match editor::update_acme_config(&state.config_path, acme) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"ok": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}
