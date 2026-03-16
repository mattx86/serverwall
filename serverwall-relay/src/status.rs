use serde::{Deserialize, Serialize};

/// Queue statistics exposed via the management API.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    pub total: usize,
    pub pending: usize,
    pub deferred: usize,
    pub held: usize,
    pub active: usize,
    pub oldest_message_age_secs: Option<u64>,
}
