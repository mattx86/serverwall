use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::schema::DmarcPolicyDomain;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// Build the DMARC DNS TXT record string for a policy domain.
fn build_dns_record(d: &DmarcPolicyDomain) -> String {
    let mut parts = vec![
        "v=DMARC1".to_string(),
        format!("p={}", d.policy),
    ];
    if let Some(sp) = &d.subdomain_policy {
        parts.push(format!("sp={}", sp));
    }
    if d.adkim != "r" {
        parts.push(format!("adkim={}", d.adkim));
    }
    if d.aspf != "r" {
        parts.push(format!("aspf={}", d.aspf));
    }
    if d.pct != 100 {
        parts.push(format!("pct={}", d.pct));
    }
    for rua in &d.rua {
        parts.push(format!("rua={}", rua));
    }
    for ruf in &d.ruf {
        parts.push(format!("ruf={}", ruf));
    }
    format!(
        "_dmarc.{}  IN TXT  \"{}\"",
        d.domain,
        parts.join("; ")
    )
}

/// GET /api/dmarc — list all configured DMARC policy domains.
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let domains: Vec<Value> = config.relay.dmarc_publish.domains.iter().map(|d| json!({
        "domain":            d.domain,
        "policy":            d.policy,
        "subdomain_policy":  d.subdomain_policy,
        "pct":               d.pct,
        "rua":               d.rua,
        "ruf":               d.ruf,
        "adkim":             d.adkim,
        "aspf":              d.aspf,
        "dns_record":        build_dns_record(d),
    })).collect();
    Json(json!({ "domains": domains }))
}

/// POST /api/dmarc — add a DMARC policy domain.
pub async fn create(
    State(state): State<AppState>,
    Json(domain): Json<DmarcPolicyDomain>,
) -> (StatusCode, Json<Value>) {
    let dns = build_dns_record(&domain);
    match editor::add_dmarc_policy_domain(&state.config_path, domain) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({ "created": true, "dns_record": dns })))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

/// PUT /api/dmarc/{domain} — update a DMARC policy domain.
pub async fn update(
    State(state): State<AppState>,
    Path(domain_name): Path<String>,
    Json(domain): Json<DmarcPolicyDomain>,
) -> (StatusCode, Json<Value>) {
    let dns = build_dns_record(&domain);
    match editor::update_dmarc_policy_domain(&state.config_path, &domain_name, domain) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({ "updated": true, "dns_record": dns })))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}

/// GET /api/dmarc/{domain}/dns — return the DNS TXT record for a configured domain.
pub async fn dns_record(
    State(state): State<AppState>,
    Path(domain_name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    match config.relay.dmarc_publish.domains.iter().find(|d| d.domain == domain_name) {
        Some(d) => (StatusCode::OK, Json(json!({ "dns_record": build_dns_record(d) }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "DMARC domain not found" }))),
    }
}

/// DELETE /api/dmarc/{domain} — remove a DMARC policy domain.
pub async fn delete(
    State(state): State<AppState>,
    Path(domain_name): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_dmarc_policy_domain(&state.config_path, &domain_name) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({ "deleted": true })))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}
