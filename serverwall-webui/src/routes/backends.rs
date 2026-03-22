use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::schema::BackendPoolConfig;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// GET /api/backends - list all backend pools
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let pools: Vec<Value> = config
        .backend_pool
        .iter()
        .map(|pool| {
            let backends: Vec<Value> = pool
                .backend
                .iter()
                .map(|b| {
                    json!({
                        "name": b.name,
                        "address": b.address,
                        "weight": b.weight,
                        "tls": b.tls,
                        "enabled": b.enabled,
                    })
                })
                .collect();

            json!({
                "name": pool.name,
                "health_check_interval": pool.health_check_interval,
                "health_check_timeout": pool.health_check_timeout,
                "health_check_type": format!("{:?}", pool.health_check_type).to_lowercase(),
                "health_check_path": pool.health_check_path,
                "backend_count": pool.backend.len(),
                "backends": backends,
            })
        })
        .collect();

    Json(json!({"pools": pools}))
}

/// GET /api/backends/:pool - get specific backend pool
pub async fn get(
    State(state): State<AppState>,
    Path(pool_name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    let pool = config.backend_pool.iter().find(|p| p.name == pool_name);

    match pool {
        Some(p) => {
            let backends: Vec<Value> = p
                .backend
                .iter()
                .map(|b| {
                    json!({
                        "name": b.name,
                        "address": b.address,
                        "weight": b.weight,
                        "tls": b.tls,
                        "enabled": b.enabled,
                    })
                })
                .collect();

            (
                StatusCode::OK,
                Json(json!({
                    "pool": {
                        "name": p.name,
                        "health_check_type":        format!("{:?}", p.health_check_type).to_lowercase(),
                        "health_check_interval":    p.health_check_interval,
                        "health_check_timeout":     p.health_check_timeout,
                        "health_check_path":        p.health_check_path,
                        "health_check_expect":      p.health_check_expect,
                        "health_check_tls":         p.health_check_tls,
                        "health_check_ignore_cert": p.health_check_ignore_cert,
                        "backends": backends,
                    }
                })),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "backend pool not found"})),
        ),
    }
}

/// POST /api/backends - add a new backend pool
pub async fn create(
    State(state): State<AppState>,
    Json(pool): Json<BackendPoolConfig>,
) -> (StatusCode, Json<Value>) {
    // Validate the new state before touching disk.
    {
        let mut test = (**state.config.load()).clone();
        test.backend_pool.push(pool.clone());
        if let Err(e) = serverwall_core::config::validate_config(&test) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": e.to_string()})),
            );
        }
    }

    match editor::add_backend_pool(&state.config_path, pool) {
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

/// PUT /api/backends/:pool - replace a backend pool's configuration
pub async fn update(
    State(state): State<AppState>,
    Path(pool_name): Path<String>,
    Json(pool): Json<BackendPoolConfig>,
) -> (StatusCode, Json<Value>) {
    {
        let mut test = (**state.config.load()).clone();
        match test.backend_pool.iter().position(|p| p.name == pool_name) {
            Some(idx) => test.backend_pool[idx] = pool.clone(),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "backend pool not found"})),
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

    match editor::update_backend_pool(&state.config_path, &pool_name, pool) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"updated": true})))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

/// DELETE /api/backends/:pool - remove a backend pool
pub async fn delete(
    State(state): State<AppState>,
    Path(pool_name): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_backend_pool(&state.config_path, &pool_name) {
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
