use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::schema::SecurityProfile;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

fn profile_json(p: &SecurityProfile) -> Value {
    json!({
        "name":         p.name,
        "description":  p.description,
        "profile_type": p.profile_type,
        "waf_enabled":  p.waf_enabled,
        "waf_ruleset": p.waf_ruleset,
        "headers": {
            "add_x_content_type_options":   p.headers.add_x_content_type_options,
            "add_x_frame_options":          p.headers.add_x_frame_options,
            "add_referrer_policy":          p.headers.add_referrer_policy,
            "add_content_security_policy":  p.headers.add_content_security_policy,
            "remove_server_header":         p.headers.remove_server_header,
            "remove_x_powered_by":          p.headers.remove_x_powered_by,
        },
        "cookies": {
            "enforce_secure_flag":   p.cookies.enforce_secure_flag,
            "enforce_httponly_flag": p.cookies.enforce_httponly_flag,
            "enforce_samesite":      p.cookies.enforce_samesite,
            "max_cookie_size":       p.cookies.max_cookie_size,
        },
        "bot_detection": {
            "enabled":                    p.bot_detection.enabled,
            "challenge_suspicious":       p.bot_detection.challenge_suspicious,
            "verify_good_bots":           p.bot_detection.verify_good_bots,
            "ja3_fingerprint_block_list": p.bot_detection.ja3_fingerprint_block_list,
            "known_good_bots":            p.bot_detection.known_good_bots,
        },
        "geo": {
            "enabled":         p.geo.enabled,
            "block_countries": p.geo.block_countries,
            "allow_countries": p.geo.allow_countries,
        },
        "min_version":             p.min_version,
        "cipher_suites":           p.cipher_suites,
        "hsts_max_age":            p.hsts_max_age,
        "hsts_include_subdomains": p.hsts_include_subdomains,
        "ocsp_stapling":           p.ocsp_stapling,
        "antispam": p.antispam.as_ref().map(|a| json!({
            "enabled":                  a.enabled,
            "possible_spam_threshold":  a.possible_spam_threshold,
            "definite_spam_threshold":  a.definite_spam_threshold,
            "antivirus": {
                "enabled":            a.antivirus.enabled,
                "weight":             a.antivirus.weight,
                "reject_on_virus":    a.antivirus.reject_on_virus,
                "on_scanner_error":   a.antivirus.on_scanner_error,
                "on_scanner_timeout": a.antivirus.on_scanner_timeout,
                "scanners": a.antivirus.scanners.iter().map(|s| json!({
                    "name":              s.name,
                    "command":           s.command,
                    "clean_exit_codes":  s.clean_exit_codes,
                    "virus_exit_codes":  s.virus_exit_codes,
                    "error_exit_codes":  s.error_exit_codes,
                    "timeout":           s.timeout,
                    "virus_name_pattern": s.virus_name_pattern,
                })).collect::<Vec<_>>(),
            },
        })),
    })
}

pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let profiles: Vec<Value> = config.security_profiles.iter().map(profile_json).collect();
    Json(json!({ "profiles": profiles }))
}

pub async fn get(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    match config.security_profiles.iter().find(|p| p.name == name) {
        Some(p) => (StatusCode::OK, Json(profile_json(p))),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "profile not found"}))),
    }
}

pub async fn create(
    State(state): State<AppState>,
    Json(profile): Json<SecurityProfile>,
) -> (StatusCode, Json<Value>) {
    match editor::add_security_profile(&state.config_path, profile) {
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
    Json(mut profile): Json<SecurityProfile>,
) -> (StatusCode, Json<Value>) {
    profile.name = name.clone();
    match editor::update_security_profile(&state.config_path, &name, profile) {
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
    match editor::remove_security_profile(&state.config_path, &name) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"deleted": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}
