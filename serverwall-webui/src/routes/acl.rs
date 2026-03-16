use axum::{extract::{Path, State}, Json};
use serde_json::{json, Value};

use crate::state::AppState;

/// GET /api/acl - list ACL configuration
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
                "default_action": format!("{:?}", f.acl.default_action).to_lowercase(),
            })
        })
        .collect();

    Json(json!({"acls": acls}))
}

pub async fn get(Path(_id): Path<String>) -> Json<Value> {
    Json(json!({"error": "ACL is managed via serverwall.toml"}))
}

pub async fn create() -> Json<Value> {
    Json(json!({"error": "ACL creation via API is not supported; edit serverwall.toml and reload"}))
}

pub async fn update(Path(_id): Path<String>) -> Json<Value> {
    Json(json!({"error": "ACL update via API is not supported; edit serverwall.toml and reload"}))
}

pub async fn delete(Path(_id): Path<String>) -> Json<Value> {
    Json(json!({"error": "ACL deletion via API is not supported; edit serverwall.toml and reload"}))
}
