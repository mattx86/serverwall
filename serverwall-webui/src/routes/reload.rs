use std::path::PathBuf;

use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use serverwall_core::{send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// POST /api/reload - reload daemon config and refresh in-memory config
pub async fn reload(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let pid_file = PathBuf::from(DEFAULT_PID_FILE);

    // Reload the webui's own in-memory config from disk
    state.reload_config();

    // Signal the main serverwall daemon to reload
    match send_reload_signal(&pid_file) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "reloaded": true,
                "message": "SIGHUP sent to serverwall daemon"
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "reloaded": false,
                "error": e.to_string(),
                "hint": "Is serverwall running? Check that the PID file exists."
            })),
        ),
    }
}
