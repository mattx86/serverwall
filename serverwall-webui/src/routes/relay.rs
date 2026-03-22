use std::path::PathBuf;

use axum::{extract::{Path, State}, http::StatusCode, Json};
use serde_json::{json, Value};

use serverwall_core::config::schema::RelayConfig;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// GET /api/relay — return the relay configuration
pub async fn get(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let r = &config.relay;
    Json(json!({
        "enabled": r.enabled,
        "listen": r.listen,
        "hostname": r.hostname,
        "spool_dir": r.spool_dir,
        "max_queue_size": r.max_queue_size,
        "delivery_threads": r.delivery_threads,
        "trusted_hosts": {
            "hosts": r.trusted_hosts.hosts,
            "require_tls": r.trusted_hosts.require_tls,
        },
        "retry": {
            "intervals": r.retry.intervals,
            "max_age": r.retry.max_age,
            "max_attempts": r.retry.max_attempts,
        },
        "tls": {
            "opportunistic": r.tls.opportunistic,
            "verify_certificates": r.tls.verify_certificates,
            "min_version": r.tls.min_version,
        },
        "outbound_policy": {
            "max_message_size": r.outbound_policy.max_message_size,
            "max_recipients_per_message": r.outbound_policy.max_recipients_per_message,
            "allowed_sender_domains": r.outbound_policy.allowed_sender_domains,
            "max_messages_per_domain_per_hour": r.outbound_policy.max_messages_per_domain_per_hour,
        },
        "dkim": {
            "enabled": r.dkim.enabled,
            "domains": r.dkim.domains.iter().map(|d| json!({
                "domain": d.domain,
                "selector": d.selector,
                "key_file": d.key_file,
                "algorithm": d.algorithm,
            })).collect::<Vec<_>>(),
        },
    }))
}

/// PUT /api/relay — replace the relay configuration
pub async fn update(
    State(state): State<AppState>,
    Json(relay): Json<RelayConfig>,
) -> (StatusCode, Json<Value>) {
    match editor::set_relay_config(&state.config_path, relay) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"ok": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}

/// POST /api/relay/trusted-hosts — add a trusted host CIDR/IP
pub async fn trusted_host_add(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let host = match body.get("host").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "host required"}))),
    };
    match editor::add_trusted_host(&state.config_path, host) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({"created": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}

/// DELETE /api/relay/trusted-hosts/{host} — remove a trusted host
pub async fn trusted_host_remove(
    State(state): State<AppState>,
    Path(host): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_trusted_host(&state.config_path, &host) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"deleted": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}
