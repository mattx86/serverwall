use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::schema::DnsblListEntry;
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// GET /api/antispam/stats - antispam configuration and status
pub async fn stats(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let a = &config.antispam;

    Json(json!({
        "enabled": a.enabled,
        "possible_spam_threshold": a.possible_spam_threshold,
        "definite_spam_threshold": a.definite_spam_threshold,
        "checks": {
            "dnsbl":        { "enabled": a.dnsbl.enabled,        "weight": a.dnsbl.weight },
            "spf":          { "enabled": a.spf.enabled,          "weight": a.spf.weight },
            "dkim":         { "enabled": a.dkim.enabled,         "weight": a.dkim.weight },
            "dmarc":        { "enabled": a.dmarc.enabled,        "weight": a.dmarc.weight },
            "rdns":         { "enabled": a.rdns.enabled,         "weight": a.rdns.weight },
            "helo":         { "enabled": a.helo.enabled,         "weight": a.helo.weight },
            "content":      { "enabled": a.content.enabled,      "weight": a.content.weight },
            "url_analysis": { "enabled": a.url_analysis.enabled, "weight": a.url_analysis.weight },
            "attachment":   { "enabled": a.attachment.enabled,   "weight": a.attachment.weight },
            "html":         { "enabled": a.html.enabled,         "weight": a.html.weight },
        },
        "dnsbl_lists":    a.dnsbl.lists.iter().map(|l| &l.zone).collect::<Vec<_>>(),
        "allow_ips":      a.allow.ips.len(),
        "allow_senders":  a.allow.senders.len(),
        "block_ips":      a.block.ips.len(),
        "block_senders":  a.block.senders.len(),
    }))
}

/// GET /api/antispam/lists - full allow list + block list + DNSBL zones
pub async fn list_entries(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let a = &config.antispam;
    let dnsbl: Vec<Value> = a.dnsbl.lists.iter().map(|z| json!({
        "zone": z.zone,
        "weight_multiplier": z.weight_multiplier,
        "reject_on_hit": z.reject_on_hit,
    })).collect();
    Json(json!({
        "allow": {
            "ips":     a.allow.ips,
            "senders": a.allow.senders,
            "domains": a.allow.sender_domains,
        },
        "block": {
            "ips":     a.block.ips,
            "senders": a.block.senders,
            "domains": a.block.sender_domains,
        },
        "dnsbl_zones": dnsbl,
    }))
}

// ---------------------------------------------------------------------------
// Allow list
// ---------------------------------------------------------------------------

pub async fn allow_add_ip(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let ip = match body.get("ip").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "ip required"}))),
    };
    apply(editor::add_antispam_allow_ip(&state.config_path, &ip), &state)
}

pub async fn allow_remove_ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> (StatusCode, Json<Value>) {
    apply(editor::remove_antispam_allow_ip(&state.config_path, &ip), &state)
}

pub async fn allow_add_sender(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let sender = match body.get("sender").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "sender required"}))),
    };
    apply(editor::add_antispam_allow_sender(&state.config_path, &sender), &state)
}

pub async fn allow_remove_sender(
    State(state): State<AppState>,
    Path(sender): Path<String>,
) -> (StatusCode, Json<Value>) {
    apply(editor::remove_antispam_allow_sender(&state.config_path, &sender), &state)
}

pub async fn allow_add_domain(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let domain = match body.get("domain").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "domain required"}))),
    };
    apply(editor::add_antispam_allow_domain(&state.config_path, &domain), &state)
}

pub async fn allow_remove_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> (StatusCode, Json<Value>) {
    apply(editor::remove_antispam_allow_domain(&state.config_path, &domain), &state)
}

// ---------------------------------------------------------------------------
// Block list
// ---------------------------------------------------------------------------

pub async fn block_add_ip(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let ip = match body.get("ip").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "ip required"}))),
    };
    apply(editor::add_antispam_block_ip(&state.config_path, &ip), &state)
}

pub async fn block_remove_ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> (StatusCode, Json<Value>) {
    apply(editor::remove_antispam_block_ip(&state.config_path, &ip), &state)
}

pub async fn block_add_sender(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let sender = match body.get("sender").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "sender required"}))),
    };
    apply(editor::add_antispam_block_sender(&state.config_path, &sender), &state)
}

pub async fn block_remove_sender(
    State(state): State<AppState>,
    Path(sender): Path<String>,
) -> (StatusCode, Json<Value>) {
    apply(editor::remove_antispam_block_sender(&state.config_path, &sender), &state)
}

pub async fn block_add_domain(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let domain = match body.get("domain").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "domain required"}))),
    };
    apply(editor::add_antispam_block_domain(&state.config_path, &domain), &state)
}

pub async fn block_remove_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> (StatusCode, Json<Value>) {
    apply(editor::remove_antispam_block_domain(&state.config_path, &domain), &state)
}

// ---------------------------------------------------------------------------
// DNSBL zones
// ---------------------------------------------------------------------------

pub async fn dnsbl_add(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let zone = match body.get("zone").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "zone required"}))),
    };
    let entry = DnsblListEntry {
        zone,
        weight_multiplier: body.get("weight_multiplier").and_then(|v| v.as_f64()).unwrap_or(1.0),
        reject_on_hit: body.get("reject_on_hit").and_then(|v| v.as_bool()).unwrap_or(false),
    };
    match editor::add_antispam_dnsbl_zone(&state.config_path, entry) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({"created": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}

pub async fn dnsbl_remove(
    State(state): State<AppState>,
    Path(zone): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_antispam_dnsbl_zone(&state.config_path, &zone) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"deleted": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn apply(
    result: serverwall_core::error::Result<()>,
    state: &AppState,
) -> (StatusCode, Json<Value>) {
    match result {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"ok": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}
