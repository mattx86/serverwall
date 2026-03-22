use std::path::PathBuf;

use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use serverwall_core::config::schema::GlobalConfig;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// GET /api/settings/global — return global daemon settings
pub async fn get(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let g = &config.global;
    Json(json!({
        "daemon_name": g.daemon_name,
        "pid_file": g.pid_file,
        "worker_threads": g.worker_threads,
        "max_connections": g.max_connections,
        "log_dir": g.log_dir,
        "cert_dir": g.cert_dir,
        "config_dir": g.config_dir,
        "log_level": g.log_level,
    }))
}

/// PUT /api/settings/global — replace global daemon settings
pub async fn update(
    State(state): State<AppState>,
    Json(global): Json<GlobalConfig>,
) -> (StatusCode, Json<Value>) {
    match editor::update_global_config(&state.config_path, global) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"ok": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}
