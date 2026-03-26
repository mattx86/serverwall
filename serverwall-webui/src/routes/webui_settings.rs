use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use serverwall_core::acl::IpMatcher;
use serverwall_core::config::editor;

use crate::state::AppState;

/// GET /api/settings/webui — return webui settings
pub async fn get(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    Json(json!({ "allow_list": config.webui.allow_list }))
}

#[derive(Deserialize)]
pub struct WebuiSettings {
    pub allow_list: Vec<String>,
}

/// PUT /api/settings/webui — replace webui settings
pub async fn update(
    State(state): State<AppState>,
    Json(body): Json<WebuiSettings>,
) -> (StatusCode, Json<Value>) {
    // Validate all CIDRs before persisting.
    if let Err(e) = IpMatcher::new(&body.allow_list) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()})));
    }
    match editor::update_webui_allow_list(&state.config_path, body.allow_list) {
        Ok(()) => {
            state.reload_config();
            (StatusCode::OK, Json(json!({"ok": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}
