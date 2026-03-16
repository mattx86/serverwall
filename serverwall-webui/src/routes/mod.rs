pub mod auth;
pub mod frontends;
pub mod backends;
pub mod certificates;
pub mod acl;
pub mod waf;
pub mod status;
pub mod logs;
pub mod reload;
pub mod queue;
pub mod antispam;

use axum::{
    middleware as axum_middleware,
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use crate::middleware;
use crate::state::AppState;
use crate::static_files;

/// Build the full Axum router with all routes.
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/", get(|| async { axum::response::Redirect::permanent("/ui/login.html") }))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/health", get(health_check))
        .route("/ui/login.html", get(static_files::serve_login))
        // Static assets (CSS, JS, images) served without auth so login page renders correctly
        .route("/ui/{*path}", get(static_files::serve_asset));

    // Protected API routes
    let api_routes = Router::new()
        // Status
        .route("/api/status", get(status::dashboard))
        // Frontends (read + write)
        .route("/api/frontends", get(frontends::list).post(frontends::create))
        .route(
            "/api/frontends/{name}",
            get(frontends::get).delete(frontends::delete),
        )
        // Backends (read + write)
        .route("/api/backends", get(backends::list).post(backends::create))
        .route(
            "/api/backends/{pool}",
            get(backends::get).delete(backends::delete),
        )
        // Queue (full CRUD)
        .route("/api/queue", get(queue::list))
        .route("/api/queue/stats", get(queue::stats))
        .route("/api/queue/flush", post(queue::flush))
        .route("/api/queue/purge", post(queue::purge))
        .route("/api/queue/{id}", get(queue::view).delete(queue::delete))
        .route("/api/queue/{id}/retry", post(queue::retry))
        .route("/api/queue/{id}/hold", post(queue::hold))
        .route("/api/queue/{id}/release", post(queue::release))
        // Certificates
        .route("/api/certs", get(certificates::list))
        .route("/api/certs/import", post(certificates::create))
        .route("/api/certs/{id}", get(certificates::get).delete(certificates::delete))
        // Antispam
        .route("/api/antispam/stats", get(antispam::stats))
        // Reload
        .route("/api/reload", post(reload::reload))
        // Logs
        .route("/api/logs", get(logs::stream))
        // ACL
        .route("/api/acl", get(acl::list).post(acl::create))
        .route("/api/acl/{id}", get(acl::get).put(acl::update).delete(acl::delete))
        // WAF
        .route("/api/waf", get(waf::list).post(waf::create))
        .route("/api/waf/{name}", get(waf::get).put(waf::update).delete(waf::delete))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::auth,
        ));

    Router::new()
        .merge(public_routes)
        .merge(api_routes)
        .layer(cors)
        .with_state(state)
}

async fn health_check() -> &'static str {
    "ok"
}
