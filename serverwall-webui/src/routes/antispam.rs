use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use serverwall_core::config::editor::AntispamChecksUpdate;
use serverwall_core::config::schema::{DnsblListEntry, DomainOverride, ScannerConfig};
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// GET /api/antispam/stats - antispam configuration and status
pub async fn stats(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let a = &config.antispam;

    Json(json!({
        "enabled":                  a.enabled,
        "possible_spam_threshold":  a.possible_spam_threshold,
        "definite_spam_threshold":  a.definite_spam_threshold,
        "max_check_duration":       a.max_check_duration,
        "checks": {
            "dnsbl":           { "enabled": a.dnsbl.enabled,           "weight": a.dnsbl.weight },
            "spf":             { "enabled": a.spf.enabled,             "weight": a.spf.weight },
            "dkim":            { "enabled": a.dkim.enabled,            "weight": a.dkim.weight },
            "dmarc":           { "enabled": a.dmarc.enabled,           "weight": a.dmarc.weight },
            "rdns":            { "enabled": a.rdns.enabled,            "weight": a.rdns.weight },
            "helo":            { "enabled": a.helo.enabled,            "weight": a.helo.weight },
            "early_talker":    { "enabled": a.early_talker.enabled,    "weight": a.early_talker.weight },
            "residential_spf": {
                "enabled":         a.residential_spf.enabled,
                "weight":          a.residential_spf.weight,
                "reject":          a.residential_spf.reject,
                "check_pbl":       a.residential_spf.check_pbl,
                "pbl_zone":        a.residential_spf.pbl_zone,
                "softfail_triggers": a.residential_spf.softfail_triggers,
            },
            "content":         { "enabled": a.content.enabled,         "weight": a.content.weight },
            "url_analysis":    { "enabled": a.url_analysis.enabled,    "weight": a.url_analysis.weight },
            "attachment":      { "enabled": a.attachment.enabled,      "weight": a.attachment.weight },
            "html":            { "enabled": a.html.enabled,            "weight": a.html.weight },
            "header_analysis": { "enabled": a.header_analysis.enabled, "weight": a.header_analysis.weight },
            "charset":         { "enabled": a.charset.enabled,         "weight": a.charset.weight },
            "bulk":            { "enabled": a.bulk.enabled,            "weight": a.bulk.weight },
            "ratio":           { "enabled": a.ratio.enabled,           "weight": a.ratio.weight },
            "antivirus": {
                "enabled":            a.antivirus.enabled,
                "weight":             a.antivirus.weight,
                "reject_on_virus":    a.antivirus.reject_on_virus,
                "on_scanner_error":   a.antivirus.on_scanner_error,
                "on_scanner_timeout": a.antivirus.on_scanner_timeout,
                "scanners": a.antivirus.scanners.iter().map(|s| json!({
                    "name":    s.name,
                    "command": s.command,
                    "timeout": s.timeout,
                })).collect::<Vec<_>>(),
            },
        },
        "dnsbl_lists":    a.dnsbl.lists.iter().map(|l| &l.zone).collect::<Vec<_>>(),
        "allow_ips":      a.allow.ips.len(),
        "allow_senders":  a.allow.senders.len(),
        "allow_domains":  a.allow.sender_domains.len(),
        "allow_recipients": a.allow.recipients.len(),
        "block_ips":      a.block.ips.len(),
        "block_senders":  a.block.senders.len(),
        "block_domains":  a.block.sender_domains.len(),
        "block_recipients": a.block.recipients.len(),
        "domain_overrides": a.domain_overrides.iter().map(|d| json!({
            "domain": d.domain,
            "possible_spam_threshold": d.possible_spam_threshold,
            "definite_spam_threshold": d.definite_spam_threshold,
            "disabled_checks": d.disabled_checks,
        })).collect::<Vec<_>>(),
    }))
}

/// PUT /api/antispam/checks - update check enabled/weight settings
pub async fn update_checks(
    State(state): State<AppState>,
    Json(body): Json<AntispamChecksUpdate>,
) -> (StatusCode, Json<Value>) {
    apply(editor::update_antispam_checks(&state.config_path, body), &state)
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
            "ips":        a.allow.ips,
            "senders":    a.allow.senders,
            "domains":    a.allow.sender_domains,
            "recipients": a.allow.recipients,
        },
        "block": {
            "ips":        a.block.ips,
            "senders":    a.block.senders,
            "domains":    a.block.sender_domains,
            "recipients": a.block.recipients,
        },
        "dnsbl_zones": dnsbl,
        "surbl_zones": a.url_analysis.surbl_zones,
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
// Allow/block recipient lists
// ---------------------------------------------------------------------------

pub async fn allow_add_recipient(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let recipient = match body.get("recipient").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "recipient required"}))),
    };
    apply(editor::add_antispam_allow_recipient(&state.config_path, &recipient), &state)
}

pub async fn allow_remove_recipient(
    State(state): State<AppState>,
    Path(recipient): Path<String>,
) -> (StatusCode, Json<Value>) {
    apply(editor::remove_antispam_allow_recipient(&state.config_path, &recipient), &state)
}

pub async fn block_add_recipient(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let recipient = match body.get("recipient").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "recipient required"}))),
    };
    apply(editor::add_antispam_block_recipient(&state.config_path, &recipient), &state)
}

pub async fn block_remove_recipient(
    State(state): State<AppState>,
    Path(recipient): Path<String>,
) -> (StatusCode, Json<Value>) {
    apply(editor::remove_antispam_block_recipient(&state.config_path, &recipient), &state)
}

// ---------------------------------------------------------------------------
// Domain overrides
// ---------------------------------------------------------------------------

pub async fn domain_overrides_list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let overrides: Vec<Value> = config.antispam.domain_overrides.iter().map(|d| json!({
        "domain": d.domain,
        "possible_spam_threshold": d.possible_spam_threshold,
        "definite_spam_threshold": d.definite_spam_threshold,
        "disabled_checks": d.disabled_checks,
    })).collect();
    Json(json!({"domain_overrides": overrides}))
}

pub async fn domain_overrides_create(
    State(state): State<AppState>,
    Json(entry): Json<DomainOverride>,
) -> (StatusCode, Json<Value>) {
    match editor::add_antispam_domain_override(&state.config_path, entry) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({"created": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}

pub async fn domain_overrides_update(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Json(entry): Json<DomainOverride>,
) -> (StatusCode, Json<Value>) {
    apply(editor::update_antispam_domain_override(&state.config_path, &domain, entry), &state)
}

pub async fn domain_overrides_delete(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_antispam_domain_override(&state.config_path, &domain) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"deleted": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}

// ---------------------------------------------------------------------------
// SURBL zones
// ---------------------------------------------------------------------------

/// POST /api/antispam/surbl-zones — add a SURBL zone
pub async fn surbl_add(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let zone = match body.get("zone").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "zone required"}))),
    };
    apply(editor::add_antispam_surbl_zone(&state.config_path, zone), &state)
}

/// DELETE /api/antispam/surbl-zones/{zone} — remove a SURBL zone
pub async fn surbl_remove(
    State(state): State<AppState>,
    Path(zone): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_antispam_surbl_zone(&state.config_path, &zone) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::OK, Json(json!({"deleted": true})))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))),
    }
}

// ---------------------------------------------------------------------------
// Antivirus scanners
// ---------------------------------------------------------------------------

/// GET /api/antispam/scanners — list all configured antivirus scanners
pub async fn scanner_list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let scanners: Vec<Value> = config.antispam.antivirus.scanners.iter().map(|s| json!({
        "name":              s.name,
        "command":           s.command,
        "clean_exit_codes":  s.clean_exit_codes,
        "virus_exit_codes":  s.virus_exit_codes,
        "error_exit_codes":  s.error_exit_codes,
        "timeout":           s.timeout,
        "virus_name_pattern": s.virus_name_pattern,
    })).collect();
    Json(json!({"scanners": scanners}))
}

/// POST /api/antispam/scanners — add an antivirus scanner
pub async fn scanner_add(
    State(state): State<AppState>,
    Json(scanner): Json<ScannerConfig>,
) -> (StatusCode, Json<Value>) {
    match editor::add_antispam_scanner(&state.config_path, scanner) {
        Ok(()) => {
            state.reload_config();
            let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));
            (StatusCode::CREATED, Json(json!({"created": true})))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))),
    }
}

/// DELETE /api/antispam/scanners/{name} — remove an antivirus scanner
pub async fn scanner_remove(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_antispam_scanner(&state.config_path, &name) {
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
