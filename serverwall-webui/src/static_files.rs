use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
};
use rust_embed::Embed;

use crate::middleware;
use crate::state::AppState;
use crate::templates::render_page;

#[derive(Embed)]
#[folder = "../web-ui/"]
struct WebUiAssets;

/// Serve the login page.
pub async fn serve_login() -> Response {
    serve_embedded_file("login.html").await
}

/// Serve any embedded static asset by path (catch-all for /ui/{*path}).
/// HTML pages (except login.html) require a valid session cookie.
pub async fn serve_asset(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    if path.ends_with(".html") && path != "login.html" {
        if !has_valid_session(&headers, &state) {
            return (
                StatusCode::FOUND,
                [(header::LOCATION, "/ui/login.html")],
            )
                .into_response();
        }
    }
    serve_embedded_file(&path).await
}

fn has_valid_session(headers: &axum::http::HeaderMap, state: &AppState) -> bool {
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("lg_session=") {
                    if middleware::validate_jwt(token, &state.jwt_secret).is_some() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

async fn serve_embedded_file(path: &str) -> Response {
    if path.ends_with(".html") {
        return match render_page(path) {
            Some(html) => Html(html).into_response(),
            None => (StatusCode::NOT_FOUND, Html("Not found".to_string())).into_response(),
        };
    }

    match WebUiAssets::get(path) {
        Some(file) => {
            let mime = if path.ends_with(".css") {
                "text/css"
            } else if path.ends_with(".js") {
                "application/javascript"
            } else if path.ends_with(".json") {
                "application/json"
            } else if path.ends_with(".png") {
                "image/png"
            } else if path.ends_with(".svg") {
                "image/svg+xml"
            } else {
                "application/octet-stream"
            };

            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime)],
                file.data.to_vec(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, Html("Not found")).into_response(),
    }
}
