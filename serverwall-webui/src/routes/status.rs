use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::state::AppState;

/// GET /api/status - overall system status
pub async fn dashboard(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let uptime = state.started_at.elapsed().as_secs();
    let queue_stats = state.refresh_queue_stats().await;

    Json(json!({
        "status": "ok",
        "uptime_seconds": uptime,
        "frontend_count": config.frontend.len(),
        "backend_pool_count": config.backend_pool.len(),
        "active_connections": 0,
        "queue_total": queue_stats.total,
        "queue_pending": queue_stats.pending,
        "queue_deferred": queue_stats.deferred,
        "queue_held": queue_stats.held,
        "relay_enabled": config.relay.enabled,
        "antispam_enabled": config.antispam.enabled,
        "waf_rulesets": config.waf_ruleset.len(),
    }))
}
