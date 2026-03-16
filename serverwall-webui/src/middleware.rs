use axum::{
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

fn validate_jwt(token: &str, secret: &str) -> Option<Claims> {
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
