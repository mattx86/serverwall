use std::path::PathBuf;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::schema::{BackendConfig, BackendPoolConfig};
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn backend_json(b: &serverwall_core::config::schema::BackendConfig) -> Value {
    json!({
        "name": b.name,
        "address": b.address,
        "weight": b.weight,
        "tls": b.tls,
        "tls_verify": b.tls_verify,
        "tls_sni": b.tls_sni,
        "max_connections": b.max_connections,
        "enabled": b.enabled,
    })
}

/// GET /api/backends - list all backend pools
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let pools: Vec<Value> = config
        .backend_pool
        .iter()
        .map(|pool| {
            let backends: Vec<Value> = pool.backend.iter().map(backend_json).collect();

            json!({
                "name": pool.name,
                "health_check_interval": pool.health_check_interval,
                "health_check_timeout": pool.health_check_timeout,
                "health_check_type": enum_str(&pool.health_check_type),
                "health_check_method": pool.health_check_method,
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
            let backends: Vec<Value> = p.backend.iter().map(backend_json).collect();

            (
                StatusCode::OK,
                Json(json!({
                    "pool": {
                        "name": p.name,
                        "health_check_type":        enum_str(&p.health_check_type),
                        "health_check_method":      p.health_check_method,
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

/// POST /api/backends/:pool/servers — add an individual backend server to a pool
pub async fn add_server(
    State(state): State<AppState>,
    Path(pool_name): Path<String>,
    Json(backend): Json<BackendConfig>,
) -> (StatusCode, Json<Value>) {
    match editor::add_backend(&state.config_path, &pool_name, backend) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({"created": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}

/// GET /api/backends/:pool/health — TCP probe each member and report reachability
pub async fn probe_health(
    State(state): State<AppState>,
    Path(pool_name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    let pool = match config.backend_pool.iter().find(|p| p.name == pool_name) {
        Some(p) => p.clone(),
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "pool not found"}))),
    };

    let mut results = serde_json::Map::new();
    for backend in &pool.backend {
        let addr = backend.address.clone();
        let start = Instant::now();
        let reachable = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
        let latency_ms = start.elapsed().as_millis() as u64;

        let latency = if reachable { Some(latency_ms) } else { None };
        results.insert(backend.name.clone(), json!({
            "reachable": reachable,
            "latency_ms": latency,
            "enabled": backend.enabled,
        }));
    }

    (StatusCode::OK, Json(json!({"pool": pool_name, "backends": results})))
}

/// DELETE /api/backends/:pool/servers/:name — remove an individual backend server by name
pub async fn remove_server(
    State(state): State<AppState>,
    Path((pool_name, backend_name)): Path<(String, String)>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_backend(&state.config_path, &pool_name, &backend_name) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"deleted": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}
