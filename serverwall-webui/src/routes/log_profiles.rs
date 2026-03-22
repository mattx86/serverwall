use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::schema::LogProfile;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

fn profile_json(p: &LogProfile) -> Value {
    json!({
        "name":        p.name,
        "description": p.description,
        "format":      serde_json::to_value(&p.format).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(),
        "access_log":  p.access_log,
    })
}

pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let profiles: Vec<Value> = config.log_profiles.iter().map(profile_json).collect();
    Json(json!({ "profiles": profiles }))
}

pub async fn get(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    match config.log_profiles.iter().find(|p| p.name == name) {
        Some(p) => (StatusCode::OK, Json(profile_json(p))),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Logging profile not found"}))),
    }
}

pub async fn create(
    State(state): State<AppState>,
    Json(profile): Json<LogProfile>,
) -> (StatusCode, Json<Value>) {
    match editor::add_log_profile(&state.config_path, profile) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({"created": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}

pub async fn update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(mut profile): Json<LogProfile>,
) -> (StatusCode, Json<Value>) {
    profile.name = name.clone();
    match editor::update_log_profile(&state.config_path, &name, profile) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"updated": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}

pub async fn delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_log_profile(&state.config_path, &name) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"deleted": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}
