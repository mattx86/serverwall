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

    // Remove existing entry then add updated one.
    if let Err(e) = editor::remove_frontend(&state.config_path, &name) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        );
    }
    match editor::add_frontend(&state.config_path, frontend) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"updated": true})))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("frontend removed but recreation failed: {}", e)})),
        ),
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

/// GET /api/frontends - list all frontends
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let frontends: Vec<Value> = config
        .frontend
        .iter()
        .map(|f| {
            json!({
                "name": f.name,
                "protocol": format!("{:?}", f.protocol).to_lowercase(),
                "listen": f.listen,
                "backend_pool": f.backend_pool,
                "balancer": format!("{:?}", f.balancer).to_lowercase(),
                "session_cookie": f.session_cookie,
                "waf_enabled": f.waf_enabled,
                "waf_ruleset": f.waf_ruleset,
                "tls_min_version": f.tls_min_version,
                "log_file": f.log_file,
                "log_format": format!("{:?}", f.log_format).to_lowercase(),
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
                    "protocol": format!("{:?}", f.protocol).to_lowercase(),
                    "listen": f.listen,
                    "backend_pool": f.backend_pool,
                    "balancer": format!("{:?}", f.balancer).to_lowercase(),
                    "session_cookie": f.session_cookie,
                    "waf_enabled": f.waf_enabled,
                    "waf_ruleset": f.waf_ruleset,
                    "tls_min_version": f.tls_min_version,
                    "log_file": f.log_file,
                    "log_format": format!("{:?}", f.log_format).to_lowercase(),
                    "max_connections": f.max_connections,
                    "tls_cert": f.tls_cert,
                    "tls_key": f.tls_key,
                    "headers": {
                        "x_forwarded_for": f.headers.x_forwarded_for,
                        "x_real_ip": f.headers.x_real_ip,
                        "x_forwarded_proto": f.headers.x_forwarded_proto,
                    },
                    "acl": {
                        "allow_list": f.acl.allow_list,
                        "block_list": f.acl.block_list,
                        "default_action": format!("{:?}", f.acl.default_action).to_lowercase(),
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
