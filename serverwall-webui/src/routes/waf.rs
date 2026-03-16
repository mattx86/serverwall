use axum::{extract::{Path, State}, Json};
use serde_json::{json, Value};

use crate::state::AppState;

/// GET /api/waf - list WAF rulesets
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let rulesets: Vec<Value> = config
        .waf_ruleset
        .iter()
        .map(|r| {
            json!({
                "name": r.name,
                "mode": format!("{:?}", r.mode).to_lowercase(),
                "anomaly_threshold": r.anomaly_threshold,
                "paranoia_level": r.paranoia_level,
            })
        })
        .collect();

    Json(json!({"waf_rules": rulesets}))
}

pub async fn get(Path(_name): Path<String>) -> Json<Value> {
    Json(json!({"error": "WAF rulesets are managed via serverwall.toml"}))
}

pub async fn create() -> Json<Value> {
    Json(json!({"error": "WAF creation via API is not supported; edit serverwall.toml and reload"}))
}

pub async fn update(Path(_name): Path<String>) -> Json<Value> {
    Json(json!({"error": "WAF update via API is not supported; edit serverwall.toml and reload"}))
}

pub async fn delete(Path(_name): Path<String>) -> Json<Value> {
    Json(json!({"error": "WAF deletion via API is not supported; edit serverwall.toml and reload"}))
}
