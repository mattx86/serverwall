use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};

use serverwall_relay::queue::{QueueStatus, QueuedMessage};

use crate::state::AppState;

#[derive(Deserialize, Default)]
pub struct QueueListParams {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub status: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct PurgeParams {
    pub days: Option<u64>,
}

/// GET /api/queue - list queued messages with pagination and filters
pub async fn list(
    State(state): State<AppState>,
    Query(params): Query<QueueListParams>,
) -> Json<Value> {
    let mut messages = state.spool.list().unwrap_or_default();

    // Apply filters
    if let Some(ref status_filter) = params.status {
        let target_status = parse_status(status_filter);
        if let Some(ts) = target_status {
            messages.retain(|m| m.metadata.status == ts);
        }
    }

    if let Some(ref sender_filter) = params.sender {
        let s = sender_filter.to_lowercase();
        messages.retain(|m| m.envelope.mail_from.to_lowercase().contains(&s));
    }

    if let Some(ref recipient_filter) = params.recipient {
        let r = recipient_filter.to_lowercase();
        messages.retain(|m| {
            m.envelope
                .rcpt_to
                .iter()
                .any(|rcpt| rcpt.to_lowercase().contains(&r))
        });
    }

    if let Some(ref date_from) = params.date_from {
        if let Ok(from) = chrono::NaiveDate::parse_from_str(date_from, "%Y-%m-%d") {
            let from_dt = from.and_hms_opt(0, 0, 0).unwrap();
            let from_utc = chrono::DateTime::<Utc>::from_naive_utc_and_offset(from_dt, Utc);
            messages.retain(|m| m.metadata.created >= from_utc);
        }
    }

    if let Some(ref date_to) = params.date_to {
        if let Ok(to) = chrono::NaiveDate::parse_from_str(date_to, "%Y-%m-%d") {
            let to_dt = to.and_hms_opt(23, 59, 59).unwrap();
            let to_utc = chrono::DateTime::<Utc>::from_naive_utc_and_offset(to_dt, Utc);
            messages.retain(|m| m.metadata.created <= to_utc);
        }
    }

    // Sort by created date descending (newest first)
    messages.sort_by(|a, b| b.metadata.created.cmp(&a.metadata.created));

    let total = messages.len();
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(50).min(500);

    let page: Vec<Value> = messages
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|m| message_to_json(&m))
        .collect();

    Json(json!({
        "messages": page,
        "total": total,
        "offset": offset,
        "limit": limit,
    }))
}

/// GET /api/queue/:id - get specific message details
pub async fn view(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.spool.dequeue(&id) {
        Ok((msg, raw_bytes)) => {
            // Parse headers from raw message
            let headers = extract_headers(&raw_bytes);

            (
                StatusCode::OK,
                Json(json!({
                    "id": msg.id,
                    "envelope": {
                        "mail_from": msg.envelope.mail_from,
                        "rcpt_to": msg.envelope.rcpt_to,
                    },
                    "metadata": {
                        "created": msg.metadata.created.to_rfc3339(),
                        "next_retry": msg.metadata.next_retry.to_rfc3339(),
                        "attempts": msg.metadata.attempts,
                        "last_error": msg.metadata.last_error,
                        "status": format!("{:?}", msg.metadata.status).to_lowercase(),
                        "size": msg.metadata.size,
                    },
                    "headers": headers,
                })),
            )
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "message not found"})),
        ),
    }
}

/// DELETE /api/queue/:id - delete a queued message
pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.spool.remove(&id) {
        Ok(()) => (StatusCode::OK, Json(json!({"deleted": true, "id": id}))),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("failed to delete message: {}", e)})),
        ),
    }
}

/// POST /api/queue/:id/retry - retry delivery now
pub async fn retry(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.spool.dequeue(&id) {
        Ok((msg, _)) => {
            let mut metadata = msg.metadata.clone();
            metadata.status = QueueStatus::Pending;
            metadata.next_retry = Utc::now();
            match state.spool.update_metadata(&id, &metadata) {
                Ok(()) => (
                    StatusCode::OK,
                    Json(json!({"retrying": true, "id": id})),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("failed to update message: {}", e)})),
                ),
            }
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "message not found"})),
        ),
    }
}

/// POST /api/queue/:id/hold - hold a message
pub async fn hold(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.spool.dequeue(&id) {
        Ok((msg, _)) => {
            let mut metadata = msg.metadata.clone();
            metadata.status = QueueStatus::Held;
            match state.spool.update_metadata(&id, &metadata) {
                Ok(()) => (StatusCode::OK, Json(json!({"held": true, "id": id}))),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("failed to hold message: {}", e)})),
                ),
            }
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "message not found"})),
        ),
    }
}

/// POST /api/queue/:id/release - release a held message
pub async fn release(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.spool.dequeue(&id) {
        Ok((msg, _)) => {
            let mut metadata = msg.metadata.clone();
            metadata.status = QueueStatus::Pending;
            metadata.next_retry = Utc::now();
            match state.spool.update_metadata(&id, &metadata) {
                Ok(()) => (
                    StatusCode::OK,
                    Json(json!({"released": true, "id": id})),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("failed to release message: {}", e)})),
                ),
            }
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "message not found"})),
        ),
    }
}

/// POST /api/queue/flush - retry all deferred messages
pub async fn flush(State(state): State<AppState>) -> Json<Value> {
    let messages = state.spool.list().unwrap_or_default();
    let mut flushed = 0;

    for msg in &messages {
        if msg.metadata.status == QueueStatus::Deferred
            || msg.metadata.status == QueueStatus::Pending
        {
            let mut metadata = msg.metadata.clone();
            metadata.status = QueueStatus::Pending;
            metadata.next_retry = Utc::now();
            if state.spool.update_metadata(&msg.id, &metadata).is_ok() {
                flushed += 1;
            }
        }
    }

    Json(json!({"flushed": flushed}))
}

/// POST /api/queue/purge - delete messages older than N days
pub async fn purge(
    State(state): State<AppState>,
    Query(params): Query<PurgeParams>,
) -> Json<Value> {
    let days = params.days.unwrap_or(7);
    let cutoff = Utc::now() - chrono::Duration::days(days as i64);
    let messages = state.spool.list().unwrap_or_default();
    let mut purged = 0;

    for msg in &messages {
        if msg.metadata.created < cutoff {
            if state.spool.remove(&msg.id).is_ok() {
                purged += 1;
            }
        }
    }

    Json(json!({"purged": purged, "days": days}))
}

/// GET /api/queue/stats - queue statistics
pub async fn stats(State(state): State<AppState>) -> Json<Value> {
    let queue_stats = state.refresh_queue_stats().await;

    Json(json!({
        "total": queue_stats.total,
        "pending": queue_stats.pending,
        "deferred": queue_stats.deferred,
        "held": queue_stats.held,
        "active": queue_stats.active,
        "oldest_message_age_secs": queue_stats.oldest_message_age_secs,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_status(s: &str) -> Option<QueueStatus> {
    match s.to_lowercase().as_str() {
        "pending" => Some(QueueStatus::Pending),
        "active" => Some(QueueStatus::Active),
        "deferred" => Some(QueueStatus::Deferred),
        "held" => Some(QueueStatus::Held),
        _ => None,
    }
}

fn message_to_json(msg: &QueuedMessage) -> Value {
    json!({
        "id": msg.id,
        "sender": msg.envelope.mail_from,
        "recipients": msg.envelope.rcpt_to,
        "status": format!("{:?}", msg.metadata.status).to_lowercase(),
        "size": msg.metadata.size,
        "created": msg.metadata.created.to_rfc3339(),
        "next_retry": msg.metadata.next_retry.to_rfc3339(),
        "attempts": msg.metadata.attempts,
        "last_error": msg.metadata.last_error,
    })
}

fn extract_headers(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let mut headers = Vec::new();

    for line in text.lines() {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    headers
}
