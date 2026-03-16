use axum::{
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../web-ui/"]
struct WebUiAssets;

/// Serve the main dashboard page.
pub async fn serve_index() -> Response {
    serve_embedded_file("index.html").await
}

/// Serve the login page.
pub async fn serve_login() -> Response {
    serve_embedded_file("login.html").await
}

/// Serve the queue management page.
pub async fn serve_queue() -> Response {
    serve_embedded_file("queue.html").await
}

async fn serve_embedded_file(path: &str) -> Response {
    match WebUiAssets::get(path) {
        Some(file) => {
            let mime = if path.ends_with(".html") {
                "text/html; charset=utf-8"
            } else if path.ends_with(".css") {
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
