use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::schema::SpfDomainConfig;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// Build the SPF DNS TXT record string for a domain config.
fn build_spf_record(d: &SpfDomainConfig) -> String {
    let mut parts = vec!["v=spf1".to_string()];
    for m in &d.mechanisms {
        let q = if m.qualifier == "+" { "" } else { &m.qualifier };
        let term = match &m.value {
            Some(v) if !v.is_empty() => format!("{}{}:{}", q, m.mechanism, v),
            _ => format!("{}{}", q, m.mechanism),
        };
        parts.push(term);
    }
    parts.push(d.all.clone());
    format!("{}  IN TXT  \"{}\"", d.domain, parts.join(" "))
}

/// GET /api/spf — list all configured SPF domains.
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let domains: Vec<Value> = config.relay.spf_publish.domains.iter().map(|d| {
        let mechs: Vec<Value> = d.mechanisms.iter().map(|m| json!({
            "qualifier": m.qualifier,
            "mechanism": m.mechanism,
            "value":     m.value,
        })).collect();
        json!({
            "domain":      d.domain,
            "mechanisms":  mechs,
            "all":         d.all,
            "spf_record":  build_spf_record(d),
        })
    }).collect();
    Json(json!({ "domains": domains }))
}

/// POST /api/spf — add an SPF domain.
pub async fn create(
    State(state): State<AppState>,
    Json(domain): Json<SpfDomainConfig>,
) -> (StatusCode, Json<Value>) {
    let record = build_spf_record(&domain);
    match editor::add_spf_domain(&state.config_path, domain) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({ "created": true, "spf_record": record })))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

/// PUT /api/spf/{domain} — update an SPF domain.
pub async fn update(
    State(state): State<AppState>,
    Path(domain_name): Path<String>,
    Json(domain): Json<SpfDomainConfig>,
) -> (StatusCode, Json<Value>) {
    let record = build_spf_record(&domain);
    match editor::update_spf_domain(&state.config_path, &domain_name, domain) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({ "updated": true, "spf_record": record })))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}

/// GET /api/spf/{domain}/record — return the SPF TXT record for a domain.
pub async fn spf_record(
    State(state): State<AppState>,
    Path(domain_name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    match config.relay.spf_publish.domains.iter().find(|d| d.domain == domain_name) {
        Some(d) => (StatusCode::OK, Json(json!({ "spf_record": build_spf_record(d) }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "SPF domain not found" }))),
    }
}

/// DELETE /api/spf/{domain} — remove an SPF domain.
pub async fn delete(
    State(state): State<AppState>,
    Path(domain_name): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_spf_domain(&state.config_path, &domain_name) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({ "deleted": true })))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}
