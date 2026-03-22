use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::editor;
use serverwall_core::config::schema::WafRulesetConfig;
use serverwall_core::{send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn ruleset_json(r: &serverwall_core::config::schema::WafRulesetConfig) -> Value {
    json!({
        "name": r.name,
        "mode": enum_str(&r.mode),
        "anomaly_threshold": r.anomaly_threshold,
        "paranoia_level": r.paranoia_level,
        "rules_dir": r.rules_dir,
        "custom_rules": r.custom_rules.iter().map(|cr| json!({
            "id":          cr.id,
            "description": cr.description,
            "phase":       cr.phase,
            "action":      cr.action,
            "match_field": cr.match_field,
            "operator":    cr.operator,
            "pattern":     cr.pattern,
        })).collect::<Vec<_>>(),
        "exclusions": {
            "paths":        r.exclusions.paths,
            "ip_addresses": r.exclusions.ip_addresses,
        },
    })
}

/// GET /api/waf — list WAF rulesets
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let rulesets: Vec<Value> = config.waf_ruleset.iter().map(ruleset_json).collect();
    Json(json!({"waf_rules": rulesets}))
}

/// GET /api/waf/:name
pub async fn get(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    match config.waf_ruleset.iter().find(|r| r.name == name) {
        Some(r) => (StatusCode::OK, Json(ruleset_json(r))),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "ruleset not found"}))),
    }
}

/// POST /api/waf — create a new WAF ruleset
pub async fn create(
    State(state): State<AppState>,
    Json(ruleset): Json<WafRulesetConfig>,
) -> (StatusCode, Json<Value>) {
    match editor::add_waf_ruleset(&state.config_path, ruleset) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({"created": true})))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

/// PUT /api/waf/:name — replace an existing WAF ruleset
pub async fn update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(mut ruleset): Json<WafRulesetConfig>,
) -> (StatusCode, Json<Value>) {
    if name == "default" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "cannot modify the default WAF ruleset"})),
        );
    }

    // Ensure the ruleset name in the body matches the URL parameter
    ruleset.name = name.clone();

    match editor::update_waf_ruleset(&state.config_path, &name, ruleset) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"updated": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}

/// POST /api/waf/:name/clone — clone a WAF ruleset under a new name
pub async fn clone_ruleset(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<Value>) {
    let new_name = match body.get("new_name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "new_name is required"}))),
    };

    let source = {
        let config = state.config.load();
        match config.waf_ruleset.iter().find(|r| r.name == name) {
            Some(r) => r.clone(),
            None => return (StatusCode::NOT_FOUND, Json(json!({"error": "ruleset not found"}))),
        }
    };

    let mut cloned = source;
    cloned.name = new_name;

    match editor::add_waf_ruleset(&state.config_path, cloned) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({"created": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}

/// DELETE /api/waf/:name — delete a WAF ruleset ("default" is protected)
pub async fn delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    if name == "default" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "cannot delete the default WAF ruleset"})),
        );
    }

    match editor::remove_waf_ruleset(&state.config_path, &name) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"deleted": true})))
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": e.to_string()})),
        ),
    }
}
