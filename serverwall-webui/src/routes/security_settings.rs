use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use serverwall_core::config::schema::{
    BotDetectionConfig, CookieSecurityConfig, GeoConfig, RateLimitConfig, RateLimitScope,
    SecurityHeadersConfig, SecurityTlsConfig,
};
use serverwall_core::{config::editor, send_reload_signal, DEFAULT_PID_FILE};

use crate::state::AppState;

/// GET /api/security — return the current security configuration
pub async fn get(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let s = &config.security;
    Json(json!({
        "tls": {
            "min_version": s.tls.min_version,
            "cipher_suites": s.tls.cipher_suites,
            "ocsp_stapling": s.tls.ocsp_stapling,
            "hsts_max_age": s.tls.hsts_max_age,
            "hsts_include_subdomains": s.tls.hsts_include_subdomains,
            "backend_tls_verify": s.tls.backend_tls_verify,
            "backend_ca_bundle": s.tls.backend_ca_bundle,
        },
        "geo": {
            "enabled": s.geo.enabled,
            "database_path": s.geo.database_path,
            "block_countries": s.geo.block_countries,
            "allow_countries": s.geo.allow_countries,
        },
        "headers": {
            "add_x_content_type_options": s.headers.add_x_content_type_options,
            "add_x_frame_options": s.headers.add_x_frame_options,
            "add_referrer_policy": s.headers.add_referrer_policy,
            "add_content_security_policy": s.headers.add_content_security_policy,
            "remove_server_header": s.headers.remove_server_header,
            "remove_x_powered_by": s.headers.remove_x_powered_by,
        },
        "bot_detection": {
            "enabled": s.bot_detection.enabled,
            "challenge_suspicious": s.bot_detection.challenge_suspicious,
            "known_good_bots": s.bot_detection.known_good_bots,
            "verify_good_bots": s.bot_detection.verify_good_bots,
            "ja3_fingerprint_block_list": s.bot_detection.ja3_fingerprint_block_list,
        },
        "cookies": {
            "enforce_secure_flag": s.cookies.enforce_secure_flag,
            "enforce_httponly_flag": s.cookies.enforce_httponly_flag,
            "enforce_samesite": s.cookies.enforce_samesite,
            "max_cookie_size": s.cookies.max_cookie_size,
        },
        "rate_limits": s.rate_limit.iter().map(|r| json!({
            "name": r.name,
            "key": r.key,
            "requests": r.requests,
            "window_secs": r.window_secs,
            "burst": r.burst,
            "scope": r.scope.as_ref().and_then(|s| serde_json::to_value(s).ok()),
        })).collect::<Vec<_>>(),
    }))
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TlsBody {
    pub min_version: Option<String>,
    pub cipher_suites: Option<Vec<String>>,
    pub ocsp_stapling: Option<bool>,
    pub hsts_max_age: Option<Option<u64>>,
    pub hsts_include_subdomains: Option<bool>,
    pub backend_tls_verify: Option<bool>,
    pub backend_ca_bundle: Option<Option<String>>,
}

/// PUT /api/security/tls
pub async fn put_tls(
    State(state): State<AppState>,
    Json(body): Json<TlsBody>,
) -> (StatusCode, Json<Value>) {
    let current = {
        let config = state.config.load();
        config.security.tls.clone()
    };
    let updated = SecurityTlsConfig {
        min_version: body.min_version.unwrap_or(current.min_version),
        cipher_suites: body.cipher_suites.unwrap_or(current.cipher_suites),
        ocsp_stapling: body.ocsp_stapling.unwrap_or(current.ocsp_stapling),
        hsts_max_age: body.hsts_max_age.unwrap_or(current.hsts_max_age),
        hsts_include_subdomains: body.hsts_include_subdomains.unwrap_or(current.hsts_include_subdomains),
        backend_tls_verify: body.backend_tls_verify.unwrap_or(current.backend_tls_verify),
        backend_ca_bundle: body.backend_ca_bundle
            .map(|v| v.map(std::path::PathBuf::from))
            .unwrap_or(current.backend_ca_bundle),
    };
    apply(editor::update_security_tls(&state.config_path, updated), &state)
}

// ---------------------------------------------------------------------------
// GeoIP
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct GeoBody {
    pub enabled: Option<bool>,
    pub database_path: Option<Option<String>>,
    pub block_countries: Option<Vec<String>>,
    pub allow_countries: Option<Vec<String>>,
}

/// PUT /api/security/geo
pub async fn put_geo(
    State(state): State<AppState>,
    Json(body): Json<GeoBody>,
) -> (StatusCode, Json<Value>) {
    let current = {
        let config = state.config.load();
        config.security.geo.clone()
    };
    let updated = GeoConfig {
        enabled: body.enabled.unwrap_or(current.enabled),
        database_path: body.database_path
            .map(|v| v.map(std::path::PathBuf::from))
            .unwrap_or(current.database_path),
        block_countries: body.block_countries.unwrap_or(current.block_countries),
        allow_countries: body.allow_countries.unwrap_or(current.allow_countries),
    };
    apply(editor::update_security_geo(&state.config_path, updated), &state)
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct HeadersBody {
    pub add_x_content_type_options: Option<bool>,
    pub add_x_frame_options: Option<Option<String>>,
    pub add_referrer_policy: Option<Option<String>>,
    pub add_content_security_policy: Option<Option<String>>,
    pub remove_server_header: Option<bool>,
    pub remove_x_powered_by: Option<bool>,
}

/// PUT /api/security/headers
pub async fn put_headers(
    State(state): State<AppState>,
    Json(body): Json<HeadersBody>,
) -> (StatusCode, Json<Value>) {
    let current = {
        let config = state.config.load();
        config.security.headers.clone()
    };
    let updated = SecurityHeadersConfig {
        add_x_content_type_options: body.add_x_content_type_options.unwrap_or(current.add_x_content_type_options),
        add_x_frame_options: body.add_x_frame_options.unwrap_or(current.add_x_frame_options),
        add_referrer_policy: body.add_referrer_policy.unwrap_or(current.add_referrer_policy),
        add_content_security_policy: body.add_content_security_policy.unwrap_or(current.add_content_security_policy),
        remove_server_header: body.remove_server_header.unwrap_or(current.remove_server_header),
        remove_x_powered_by: body.remove_x_powered_by.unwrap_or(current.remove_x_powered_by),
    };
    apply(editor::update_security_headers(&state.config_path, updated), &state)
}

// ---------------------------------------------------------------------------
// Bot detection
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct BotBody {
    pub enabled: Option<bool>,
    pub challenge_suspicious: Option<bool>,
    pub known_good_bots: Option<Vec<String>>,
    pub verify_good_bots: Option<bool>,
    pub ja3_fingerprint_block_list: Option<Vec<String>>,
}

/// PUT /api/security/bot
pub async fn put_bot(
    State(state): State<AppState>,
    Json(body): Json<BotBody>,
) -> (StatusCode, Json<Value>) {
    let current = {
        let config = state.config.load();
        config.security.bot_detection.clone()
    };
    let updated = BotDetectionConfig {
        enabled: body.enabled.unwrap_or(current.enabled),
        challenge_suspicious: body.challenge_suspicious.unwrap_or(current.challenge_suspicious),
        known_good_bots: body.known_good_bots.unwrap_or(current.known_good_bots),
        verify_good_bots: body.verify_good_bots.unwrap_or(current.verify_good_bots),
        ja3_fingerprint_block_list: body.ja3_fingerprint_block_list.unwrap_or(current.ja3_fingerprint_block_list),
    };
    apply(editor::update_security_bot(&state.config_path, updated), &state)
}

// ---------------------------------------------------------------------------
// Cookie security
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CookiesBody {
    pub enforce_secure_flag: Option<bool>,
    pub enforce_httponly_flag: Option<bool>,
    pub enforce_samesite: Option<Option<String>>,
    pub max_cookie_size: Option<usize>,
}

/// PUT /api/security/cookies
pub async fn put_cookies(
    State(state): State<AppState>,
    Json(body): Json<CookiesBody>,
) -> (StatusCode, Json<Value>) {
    let current = {
        let config = state.config.load();
        config.security.cookies.clone()
    };
    let updated = CookieSecurityConfig {
        enforce_secure_flag: body.enforce_secure_flag.unwrap_or(current.enforce_secure_flag),
        enforce_httponly_flag: body.enforce_httponly_flag.unwrap_or(current.enforce_httponly_flag),
        enforce_samesite: body.enforce_samesite.unwrap_or(current.enforce_samesite),
        max_cookie_size: body.max_cookie_size.unwrap_or(current.max_cookie_size),
    };
    apply(editor::update_security_cookies(&state.config_path, updated), &state)
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RateLimitBody {
    pub name: String,
    pub key: Option<String>,
    pub requests: u64,
    pub window_secs: u64,
    pub burst: Option<u64>,
    pub scope: Option<RateLimitScope>,
}

/// POST /api/security/rate-limits
pub async fn add_rate_limit(
    State(state): State<AppState>,
    Json(body): Json<RateLimitBody>,
) -> (StatusCode, Json<Value>) {
    let rule = RateLimitConfig {
        name: body.name,
        key: body.key.unwrap_or_else(|| "ip".to_string()),
        requests: body.requests,
        window_secs: body.window_secs,
        burst: body.burst,
        scope: body.scope,
    };
    apply(editor::add_security_rate_limit(&state.config_path, rule), &state)
}

/// DELETE /api/security/rate-limits/{name}
pub async fn remove_rate_limit(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    match editor::remove_security_rate_limit(&state.config_path, &name) {
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
