use axum::{extract::State, http::StatusCode, Json};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::middleware::Claims;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
}

/// POST /api/auth/login
///
/// Accepts { username, password }, verifies against web-users.toml, returns JWT.
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> (StatusCode, Json<Value>) {
    match verify_web_user(&req.username, &req.password, &state) {
        Ok(true) => {
            let exp = chrono::Utc::now()
                .checked_add_signed(chrono::Duration::hours(24))
                .unwrap()
                .timestamp() as usize;

            let claims = Claims {
                sub: req.username.clone(),
                exp,
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
            )
            .unwrap_or_default();

            (
                StatusCode::OK,
                Json(json!({
                    "token": token,
                    "username": req.username,
                })),
            )
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid username or password"})),
        ),
    }
}

/// POST /api/auth/logout
pub async fn logout() -> Json<Value> {
    Json(json!({"status": "logged_out"}))
}

/// Verify username/password against web-users.toml.
///
/// File format:
/// ```toml
/// [[user]]
/// username = "admin"
/// password_hash = "$argon2id$..."
/// ```
fn verify_web_user(username: &str, password: &str, state: &AppState) -> anyhow::Result<bool> {
    let config = state.config.load();
    let users_file = &config.webui.web_users_file;

    let content = std::fs::read_to_string(users_file)?;

    #[derive(serde::Deserialize)]
    struct UsersFile {
        #[serde(default)]
        user: Vec<UserEntry>,
    }

    #[derive(serde::Deserialize)]
    struct UserEntry {
        username: String,
        password_hash: String,
    }

    let users: UsersFile = toml::from_str(&content)?;

    use argon2::Argon2;
    use argon2::password_hash::PasswordHash;
    use argon2::PasswordVerifier;

    for user in &users.user {
        if user.username == username {
            if let Ok(parsed_hash) = PasswordHash::new(&user.password_hash) {
                if Argon2::default()
                    .verify_password(password.as_bytes(), &parsed_hash)
                    .is_ok()
                {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
    }

    Ok(false)
}
