use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// GET /api/acl — list per-frontend ACL configuration (read-only)
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let acls: Vec<Value> = config
        .frontend
        .iter()
        .map(|f| {
            json!({
                "frontend": f.name,
                "allow_list": f.acl.allow_list,
                "block_list": f.acl.block_list,
                "default_action": serde_json::to_value(&f.acl.default_action).ok().and_then(|j| j.as_str().map(str::to_owned)).unwrap_or_default(),
            })
        })
        .collect();
    Json(json!({"acls": acls}))
}

/// GET /api/acl/global — return the global security.acl.ip allow + block lists
pub async fn global_list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    Json(json!({
        "allow": config.security.acl.ip.allow,
        "block": config.security.acl.ip.block,
    }))
}

/// POST /api/acl/global/allow — add an IP/CIDR to the global allow list
pub async fn global_allow_add(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let ip = match body.get("ip").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "ip required"}))),
    };
    apply(editor::add_acl_allow(&state.config_path, &ip), &state)
}

/// DELETE /api/acl/global/allow/{ip} — remove an IP from the global allow list
pub async fn global_allow_remove(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> (StatusCode, Json<Value>) {
    apply(editor::remove_acl_ip(&state.config_path, &ip), &state)
}

/// POST /api/acl/global/block — add an IP/CIDR to the global block list
pub async fn global_block_add(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let ip = match body.get("ip").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "ip required"}))),
    };
    apply(editor::add_acl_block(&state.config_path, &ip), &state)
}

/// DELETE /api/acl/global/block/{ip} — remove an IP from the global block list
pub async fn global_block_remove(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> (StatusCode, Json<Value>) {
    apply(editor::remove_acl_ip(&state.config_path, &ip), &state)
}

fn apply(
    result: serverwall_core::error::Result<()>,
    state: &AppState,
) -> (StatusCode, Json<Value>) {
    match result {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"ok": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}

// Legacy stubs kept for compatibility — return 404 with redirect hint
pub async fn get(Path(_id): Path<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({"error": "use /api/acl/global for global IP ACL management"})))
}
pub async fn create() -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({"error": "use /api/acl/global/allow or /api/acl/global/block"})))
}
pub async fn update(Path(_id): Path<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({"error": "use /api/acl/global for global IP ACL management"})))
}
pub async fn delete(Path(_id): Path<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({"error": "use /api/acl/global/allow or /api/acl/global/block"})))
}
