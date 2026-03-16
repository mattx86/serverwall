use axum::Json;
use serde_json::{json, Value};

/// GET /api/logs - log streaming placeholder.
///
/// In a full implementation this would use SSE or WebSocket to stream logs.
pub async fn stream() -> Json<Value> {
    Json(json!({
        "logs": [],
        "message": "log streaming is not yet implemented; check log files directly"
    }))
}
