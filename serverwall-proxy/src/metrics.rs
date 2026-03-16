use std::time::Instant;

/// Tracks per-connection metrics such as bytes transferred, duration, and status.
pub struct ConnectionMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub started_at: Instant,
}

impl ConnectionMetrics {
    pub fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            started_at: Instant::now(),
        }
    }
}
