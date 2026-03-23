use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::schema::FrontendConfig;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// POST /api/frontends - add a new frontend to the config
pub async fn create(
    State(state): State<AppState>,
    Json(frontend): Json<FrontendConfig>,
) -> (StatusCode, Json<Value>) {
    // Validate the new state before touching disk.
    {
        let mut test = (**state.config.load()).clone();
        test.frontend.push(frontend.clone());
        if let Err(e) = serverwall_core::config::validate_config(&test) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": e.to_string()})),
            );
        }
    }

    match editor::add_frontend(&state.config_path, frontend) {
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

/// PUT /api/frontends/:name - update an existing frontend
pub async fn update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(mut frontend): Json<FrontendConfig>,
) -> (StatusCode, Json<Value>) {
    frontend.name = name.clone();

    // Validate the proposed new state before touching disk.
    {
        let mut test = (**state.config.load()).clone();
        match test.frontend.iter().position(|f| f.name == name) {
            Some(idx) => test.frontend[idx] = frontend.clone(),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "frontend not found"})),
                )
            }
        }
        if let Err(e) = serverwall_core::config::validate_config(&test) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": e.to_string()})),
            );
        }
    }

    match editor::update_frontend(&state.config_path, &name, frontend) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"updated": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}

/// DELETE /api/frontends/:name - remove a frontend from the config
pub async fn delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_frontend(&state.config_path, &name) {
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

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// GET /api/frontends - list all frontends
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let frontends: Vec<Value> = config
        .frontend
        .iter()
        .map(|f| {
            json!({
                "name": f.name,
                "protocol": enum_str(&f.protocol),
                "listen": f.listen,
                "backend_pool": f.backend_pool,
                "balancer": enum_str(&f.balancer),
                "session_cookie": f.session_cookie,
                "waf_enabled": f.waf_enabled,
                "waf_ruleset": f.waf_ruleset,
                "security_profile": f.security_profile,
                "tls_min_version": f.tls_min_version,
                "access_log": f.access_log,
                "log_file": f.log_file,
                "log_format": enum_str(&f.log_format),
                "log_profile": f.log_profile,
                "max_connections": f.max_connections,
            })
        })
        .collect();

    Json(json!({"frontends": frontends}))
}

/// GET /api/frontends/:name - get specific frontend details
pub async fn get(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    let frontend = config.frontend.iter().find(|f| f.name == name);

    match frontend {
        Some(f) => (
            StatusCode::OK,
            Json(json!({
                "frontend": {
                    "name": f.name,
                    "protocol": enum_str(&f.protocol),
                    "listen": f.listen,
                    "backend_pool": f.backend_pool,
                    "balancer": enum_str(&f.balancer),
                    "session_cookie": f.session_cookie,
                    "waf_enabled": f.waf_enabled,
                    "waf_ruleset": f.waf_ruleset,
                    "security_profile": f.security_profile,
                        "tls_cert": f.tls_cert,
                    "tls_chain": f.tls_chain,
                    "tls_key": f.tls_key,
                    "tls_key_password": f.tls_key_password,
                    "tls_pfx": f.tls_pfx,
                    "tls_pfx_password": f.tls_pfx_password,
                    "tls_min_version": f.tls_min_version,
                    "tls_ciphers": f.tls_ciphers,
                    "access_log": f.access_log,
                    "log_file": f.log_file,
                    "log_format": enum_str(&f.log_format),
                    "log_profile": f.log_profile,
                    "max_connections": f.max_connections,
                    "headers": {
                        "x_forwarded_for": f.headers.x_forwarded_for,
                        "x_real_ip": f.headers.x_real_ip,
                        "x_forwarded_proto": f.headers.x_forwarded_proto,
                        "x_forwarded_host": f.headers.x_forwarded_host,
                        "x_forwarded_port": f.headers.x_forwarded_port,
                        "x_request_id": f.headers.x_request_id,
                        "custom": f.headers.custom,
                    },
                    "smtp_headers": {
                        "add_received": f.smtp_headers.add_received,
                        "x_forwarded_for": f.smtp_headers.x_forwarded_for,
                    },
                    "acl": {
                        "allow_list": f.acl.allow_list,
                        "block_list": f.acl.block_list,
                        "default_action": enum_str(&f.acl.default_action),
                    },
                }
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "frontend not found"})),
        ),
    }
}
