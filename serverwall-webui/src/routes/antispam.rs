use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::state::AppState;

/// GET /api/antispam/stats - antispam statistics
pub async fn stats(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();

    // In a full implementation, these would be tracked by shared atomic counters
    // updated by the antispam pipeline. For now, return the configuration state
    // and placeholder counters.
    Json(json!({
        "enabled": config.antispam.enabled,
        "total_scanned": 0,
        "spam_detected": 0,
        "suspect_detected": 0,
        "clean_detected": 0,
        "possible_spam_threshold": config.antispam.possible_spam_threshold,
        "definite_spam_threshold": config.antispam.definite_spam_threshold,
        "checks": {
            "dnsbl": config.antispam.dnsbl.enabled,
            "spf": config.antispam.spf.enabled,
            "dkim": config.antispam.dkim.enabled,
            "dmarc": config.antispam.dmarc.enabled,
            "content": config.antispam.content.enabled,
            "url_analysis": config.antispam.url_analysis.enabled,
            "attachment": config.antispam.attachment.enabled,
            "html": config.antispam.html.enabled,
            "rdns": config.antispam.rdns.enabled,
            "helo": config.antispam.helo.enabled,
        }
    }))
}
