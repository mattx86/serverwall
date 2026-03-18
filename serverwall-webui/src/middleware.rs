use std::net::{IpAddr, Ipv4Addr};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

/// Authentication middleware.
///
/// Skips auth for login endpoints and static UI assets.
/// Accepts either:
///   - Bearer token in Authorization header (API tokens or JWT)
///   - `lg_session` cookie containing a JWT
pub async fn auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    // Skip auth for login endpoints and static UI files
    if path == "/api/auth/login"
        || path.starts_with("/ui/login")
        || path == "/ui/login.html"
        || path == "/health"
    {
        return next.run(request).await;
    }

    // Try Bearer token from Authorization header
    if let Some(auth_header) = request.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                // Try JWT validation
                if validate_jwt(token, &state.jwt_secret).is_some() {
                    return next.run(request).await;
                }
                // Try API token validation from api-tokens.toml
                if validate_api_token(token, &state).await {
                    return next.run(request).await;
                }
            }
        }
    }

    // Try session cookie
    if let Some(cookie_header) = request.headers().get(header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("lg_session=") {
                    if validate_jwt(token, &state.jwt_secret).is_some() {
                        return next.run(request).await;
                    }
                }
            }
        }
    }

    // For UI paths, redirect to login
    if path.starts_with("/ui/") && path != "/ui/login.html" {
        return (
            StatusCode::FOUND,
            [(header::LOCATION, "/ui/login.html")],
        )
            .into_response();
    }

    // For API paths, return 401
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": "authentication required"})),
    )
        .into_response()
}

pub fn validate_jwt(token: &str, secret: &str) -> Option<Claims> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::default();
    decode::<Claims>(token, &key, &validation)
        .ok()
        .map(|data| data.claims)
}

/// Validate an API token against api-tokens.toml.
///
/// The tokens file format is:
/// ```toml
/// [[token]]
/// name = "my-token"
/// hash = "$argon2id$..."
/// ```
async fn validate_api_token(token: &str, state: &AppState) -> bool {
    let config = state.config.load();
    let tokens_file = &config.webui.tokens_file;

    let content = match std::fs::read_to_string(tokens_file) {
        Ok(c) => c,
        Err(_) => return false,
    };

    #[derive(Deserialize)]
    struct TokensFile {
        #[serde(default)]
        token: Vec<TokenEntry>,
    }

    #[derive(Deserialize)]
    struct TokenEntry {
        #[allow(dead_code)]
        name: String,
        hash: String,
    }

    let tokens: TokensFile = match toml::from_str(&content) {
        Ok(t) => t,
        Err(_) => return false,
    };

    use argon2::Argon2;
    use argon2::password_hash::PasswordHash;
    use argon2::PasswordVerifier;

    for entry in &tokens.token {
        if let Ok(parsed_hash) = PasswordHash::new(&entry.hash) {
            if Argon2::default()
                .verify_password(token.as_bytes(), &parsed_hash)
                .is_ok()
            {
                return true;
            }
        }
    }

    false
}

/// WAF middleware — runs every API request through the WAF engine.
///
/// Buffers the request body (≤ 1 MiB), inspects URI + headers + body,
/// and returns 403 if the WAF verdict is Block.
pub async fn waf_check(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let client_ip = extract_client_ip(request.headers());

    // Consume the body so we can inspect it, then reconstruct.
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(b)  => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                axum::Json(serde_json::json!({"error": "request body too large"})),
            )
                .into_response();
        }
    };

    // Build WAF context from request parts.
    let mut headers_map = std::collections::HashMap::new();
    for (k, v) in parts.headers.iter() {
        if let Ok(v_str) = v.to_str() {
            headers_map.insert(k.as_str().to_string(), v_str.to_string());
        }
    }

    let ctx = serverwall_waf::HttpRequestContext::from_parts(
        parts.method.as_str(),
        &parts.uri.to_string(),
        headers_map,
        body_bytes.to_vec(),
        client_ip,
    );

    let verdict = state.waf_engine.inspect(&ctx);

    if verdict.decision.is_blocked() {
        tracing::warn!(
            method = %parts.method,
            uri    = %parts.uri,
            score  = verdict.anomaly_score,
            rules  = ?verdict.matched_rules,
            "webui WAF: request blocked",
        );
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "Forbidden"})),
        )
            .into_response();
    }

    // Reconstruct the request with the buffered body.
    let request = Request::from_parts(parts, Body::from(body_bytes));
    next.run(request).await
}

fn extract_client_ip(headers: &axum::http::HeaderMap) -> IpAddr {
    if let Some(fwd) = headers.get("x-forwarded-for") {
        if let Ok(s) = fwd.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse() {
                    return ip;
                }
            }
        }
    }
    if let Some(real) = headers.get("x-real-ip") {
        if let Ok(s) = real.to_str() {
            if let Ok(ip) = s.trim().parse() {
                return ip;
            }
        }
    }
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}
