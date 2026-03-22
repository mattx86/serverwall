use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::schema::TlsProfile;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

fn profile_json(p: &TlsProfile) -> Value {
    json!({
        "name":                   p.name,
        "description":            p.description,
        "min_version":            p.min_version,
        "cipher_suites":          p.cipher_suites,
        "hsts_max_age":           p.hsts_max_age,
        "hsts_include_subdomains": p.hsts_include_subdomains,
        "ocsp_stapling":          p.ocsp_stapling,
    })
}

pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let profiles: Vec<Value> = config.tls_profiles.iter().map(profile_json).collect();
    Json(json!({ "profiles": profiles }))
}

pub async fn get(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    match config.tls_profiles.iter().find(|p| p.name == name) {
        Some(p) => (StatusCode::OK, Json(profile_json(p))),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "TLS profile not found"}))),
    }
}

pub async fn create(
    State(state): State<AppState>,
    Json(profile): Json<TlsProfile>,
) -> (StatusCode, Json<Value>) {
    match editor::add_tls_profile(&state.config_path, profile) {
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
    Json(mut profile): Json<TlsProfile>,
) -> (StatusCode, Json<Value>) {
    profile.name = name.clone();
    match editor::update_tls_profile(&state.config_path, &name, profile) {
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
    match editor::remove_tls_profile(&state.config_path, &name) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"deleted": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}
