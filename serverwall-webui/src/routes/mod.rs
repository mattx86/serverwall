pub mod auth;
pub mod frontends;
pub mod backends;
pub mod certificates;
pub mod acl;
pub mod dkim;
pub mod dmarc_policy;
pub mod spf;
pub mod waf;
pub mod status;
pub mod logs;
pub mod reload;
pub mod queue;
pub mod antispam;
pub mod system;
pub mod security_settings;
pub mod security_profiles;
pub mod tls_profiles;
pub mod log_profiles;
pub mod relay;
pub mod global_settings;
pub mod acme_settings;

use axum::{
    extract::{Request, State},
    middleware as axum_middleware,
    routing::{get, post},
    Router,
};
use axum::http::HeaderValue;
use tower_http::cors::{Any, CorsLayer};

use crate::middleware;
use crate::state::AppState;
use crate::static_files;

/// Build the full Axum router with all routes.
pub fn build_router(state: AppState) -> Router {
    let cors = {
        let origins = state.config.load().webui.allowed_origins.clone();
        if origins.is_empty() {
            CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any)
        } else {
            let parsed: Vec<HeaderValue> = origins.iter()
                .filter_map(|o| o.parse().ok())
                .collect();
            CorsLayer::new()
                .allow_origin(parsed)
                .allow_methods(Any)
                .allow_headers(Any)
        }
    };

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/", get(root_redirect))
        .route("/ui", get(root_redirect))
        .route("/ui/", get(root_redirect))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/captcha", get(auth::captcha))
        .route("/health", get(health_check))
        .route("/ui/login.html", get(static_files::serve_login))
        // Static assets served here; HTML pages check session cookie inside serve_asset
        .route("/ui/{*path}", get(static_files::serve_asset));

    // Protected API routes
    let api_routes = Router::new()
        // Status
        .route("/api/status", get(status::dashboard))
        // Frontends (read + write)
        .route("/api/frontends", get(frontends::list).post(frontends::create))
        .route(
            "/api/frontends/{name}",
            get(frontends::get).put(frontends::update).delete(frontends::delete),
        )
        // Backends (read + write)
        .route("/api/backends", get(backends::list).post(backends::create))
        .route(
            "/api/backends/{pool}",
            get(backends::get).put(backends::update).delete(backends::delete),
        )
        .route("/api/backends/{pool}/health", get(backends::probe_health))
        .route("/api/backends/{pool}/servers", post(backends::add_server))
        .route("/api/backends/{pool}/servers/{name}", axum::routing::delete(backends::remove_server))
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
        .route("/api/certs/import", post(certificates::import))
        .route("/api/certs/self-signed", post(certificates::generate_self_signed))
        .route("/api/certs/acme", post(certificates::acme_request))
        .route("/api/certs/{name}", get(certificates::get).delete(certificates::delete))
        // DKIM
        .route("/api/dkim", get(dkim::list))
        .route("/api/dkim/generate", post(dkim::generate))
        .route("/api/dkim/{domain}/dns", get(dkim::dns_record))
        .route("/api/dkim/{domain}", axum::routing::delete(dkim::delete))
        // DMARC publish
        .route("/api/dmarc", get(dmarc_policy::list).post(dmarc_policy::create))
        .route("/api/dmarc/{domain}/dns", get(dmarc_policy::dns_record))
        .route(
            "/api/dmarc/{domain}",
            axum::routing::put(dmarc_policy::update).delete(dmarc_policy::delete),
        )
        // SPF publish
        .route("/api/spf", get(spf::list).post(spf::create))
        .route("/api/spf/{domain}/record", get(spf::spf_record))
        .route(
            "/api/spf/{domain}",
            axum::routing::put(spf::update).delete(spf::delete),
        )
        // Antispam
        .route("/api/antispam/stats", get(antispam::stats))
        .route("/api/antispam/checks", axum::routing::put(antispam::update_checks))
        .route("/api/antispam/lists", get(antispam::list_entries))
        // Antispam allow list
        .route("/api/antispam/allow/ips", post(antispam::allow_add_ip))
        .route("/api/antispam/allow/ips/{ip}", axum::routing::delete(antispam::allow_remove_ip))
        .route("/api/antispam/allow/senders", post(antispam::allow_add_sender))
        .route("/api/antispam/allow/senders/{sender}", axum::routing::delete(antispam::allow_remove_sender))
        .route("/api/antispam/allow/domains", post(antispam::allow_add_domain))
        .route("/api/antispam/allow/domains/{domain}", axum::routing::delete(antispam::allow_remove_domain))
        // Antispam block list
        .route("/api/antispam/block/ips", post(antispam::block_add_ip))
        .route("/api/antispam/block/ips/{ip}", axum::routing::delete(antispam::block_remove_ip))
        .route("/api/antispam/block/senders", post(antispam::block_add_sender))
        .route("/api/antispam/block/senders/{sender}", axum::routing::delete(antispam::block_remove_sender))
        .route("/api/antispam/block/domains", post(antispam::block_add_domain))
        .route("/api/antispam/block/domains/{domain}", axum::routing::delete(antispam::block_remove_domain))
        .route("/api/antispam/block/recipients", post(antispam::block_add_recipient))
        .route("/api/antispam/block/recipients/{recipient}", axum::routing::delete(antispam::block_remove_recipient))
        // Antispam allow recipients
        .route("/api/antispam/allow/recipients", post(antispam::allow_add_recipient))
        .route("/api/antispam/allow/recipients/{recipient}", axum::routing::delete(antispam::allow_remove_recipient))
        // DNSBL zones
        .route("/api/antispam/dnsbl", post(antispam::dnsbl_add))
        .route("/api/antispam/dnsbl/{zone}", axum::routing::delete(antispam::dnsbl_remove))
        // Antispam domain overrides
        .route("/api/antispam/domain-overrides", get(antispam::domain_overrides_list).post(antispam::domain_overrides_create))
        .route("/api/antispam/domain-overrides/{domain}", axum::routing::put(antispam::domain_overrides_update).delete(antispam::domain_overrides_delete))
        // SURBL zones
        .route("/api/antispam/surbl-zones", post(antispam::surbl_add))
        .route("/api/antispam/surbl-zones/{zone}", axum::routing::delete(antispam::surbl_remove))
        // Antivirus scanners
        .route("/api/antispam/scanners", get(antispam::scanner_list).post(antispam::scanner_add))
        .route("/api/antispam/scanners/{name}", axum::routing::delete(antispam::scanner_remove))
        // Reload
        .route("/api/reload", post(reload::reload))
        // Logs
        .route("/api/logs", get(logs::stream))
        // ACL (per-frontend read-only + global management)
        .route("/api/acl", get(acl::list).post(acl::create))
        .route("/api/acl/global", get(acl::global_list))
        .route("/api/acl/global/allow", post(acl::global_allow_add))
        .route("/api/acl/global/allow/{ip}", axum::routing::delete(acl::global_allow_remove))
        .route("/api/acl/global/block", post(acl::global_block_add))
        .route("/api/acl/global/block/{ip}", axum::routing::delete(acl::global_block_remove))
        .route("/api/acl/{id}", get(acl::get).put(acl::update).delete(acl::delete))
        // WAF
        .route("/api/waf", get(waf::list).post(waf::create))
        .route("/api/waf/{name}", get(waf::get).put(waf::update).delete(waf::delete))
        .route("/api/waf/{name}/clone", post(waf::clone_ruleset))
        // Security profiles
        .route("/api/security-profiles", get(security_profiles::list).post(security_profiles::create))
        .route("/api/security-profiles/{name}", get(security_profiles::get)
            .put(security_profiles::update)
            .delete(security_profiles::delete))
        // TLS profiles
        .route("/api/tls-profiles", get(tls_profiles::list).post(tls_profiles::create))
        .route("/api/tls-profiles/{name}", get(tls_profiles::get)
            .put(tls_profiles::update)
            .delete(tls_profiles::delete))
        // Logging profiles
        .route("/api/log-profiles", get(log_profiles::list).post(log_profiles::create))
        .route("/api/log-profiles/{name}", get(log_profiles::get)
            .put(log_profiles::update)
            .delete(log_profiles::delete))
        // Security settings
        .route("/api/security", get(security_settings::get))
        .route("/api/security/tls", axum::routing::put(security_settings::put_tls))
        .route("/api/security/geo", axum::routing::put(security_settings::put_geo))
        .route("/api/security/headers", axum::routing::put(security_settings::put_headers))
        .route("/api/security/bot", axum::routing::put(security_settings::put_bot))
        .route("/api/security/cookies", axum::routing::put(security_settings::put_cookies))
        .route("/api/security/rate-limits", post(security_settings::add_rate_limit))
        .route("/api/security/rate-limits/{name}", axum::routing::delete(security_settings::remove_rate_limit))
        // Relay
        .route("/api/relay", get(relay::get).put(relay::update))
        .route("/api/relay/trusted-hosts", post(relay::trusted_host_add))
        .route("/api/relay/trusted-hosts/{host}", axum::routing::delete(relay::trusted_host_remove))
        // Global and ACME settings
        .route("/api/settings/global", get(global_settings::get).put(global_settings::update))
        .route("/api/settings/acme", get(acme_settings::get).put(acme_settings::update))
        // System
        .route("/api/system/webui-cert", post(system::set_webui_cert))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::auth,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::waf_check,
        ));

    Router::new()
        .merge(public_routes)
        .merge(api_routes)
        .layer(cors)
        .with_state(state)
}

async fn root_redirect(
    State(state): State<AppState>,
    request: Request,
) -> axum::response::Redirect {
    // If the request carries a valid session cookie, send to dashboard.
    if let Some(cookie_header) = request.headers().get(axum::http::header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("lg_session=") {
                    if middleware::validate_jwt(token, &state.jwt_secret).is_some() {
                        return axum::response::Redirect::to("/ui/index.html");
                    }
                }
            }
        }
    }
    axum::response::Redirect::to("/ui/login.html")
}

async fn health_check() -> &'static str {
    "ok"
}
