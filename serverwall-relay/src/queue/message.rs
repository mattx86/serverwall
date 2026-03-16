use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A message sitting in the outbound queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    /// Unique message identifier.
    pub id: String,
    /// Envelope sender and recipients.
    pub envelope: Envelope,
    /// Additional metadata (timestamps, retry count, etc.).
    pub metadata: MessageMetadata,
}

/// SMTP envelope information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
}

/// Metadata attached to a queued message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub created: DateTime<Utc>,
    pub next_retry: DateTime<Utc>,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub status: QueueStatus,
    pub size: usize,
}

/// Queue status for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    Pending,
    Active,
    Deferred,
    Held,
}
