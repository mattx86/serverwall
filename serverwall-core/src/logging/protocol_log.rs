use std::net::SocketAddr;

use chrono::{DateTime, Utc};

/// A single protocol-level connection log entry.
///
/// Format:
/// ```text
/// <timestamp> <client_ip>:<port> -> <backend_ip>:<port> bytes_in=<N> bytes_out=<N> duration=<secs>
/// ```
pub struct ProtocolLogEntry {
    /// Timestamp of the log entry
    pub timestamp: DateTime<Utc>,
    /// Client socket address (IP:port)
    pub client: SocketAddr,
    /// Backend socket address (IP:port)
    pub backend: SocketAddr,
    /// Bytes received from client
    pub bytes_in: u64,
    /// Bytes sent to client
    pub bytes_out: u64,
    /// Connection duration in fractional seconds
    pub duration_secs: f64,
}

impl ProtocolLogEntry {
    /// Format this entry as a protocol connection log line.
    pub fn format(&self) -> String {
        let timestamp = self.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ");
        format!(
            "{} {} -> {} bytes_in={} bytes_out={} duration={:.3}",
            timestamp,
            self.client,
            self.backend,
            self.bytes_in,
            self.bytes_out,
            self.duration_secs,
        )
    }
}

/// Direction of protocol data flow.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    ClientToBackend,
    BackendToClient,
}

/// Formats detailed protocol-level log entries for debugging (convenience wrapper).
pub struct ProtocolLogFormatter {
    /// Whether to include raw payload bytes in the log.
    include_payload: bool,
}

impl ProtocolLogFormatter {
    pub fn new(include_payload: bool) -> Self {
        Self { include_payload }
    }

    /// Format a protocol event log line.
    pub fn format(
        &self,
        direction: Direction,
        client: SocketAddr,
        backend: SocketAddr,
        protocol: &str,
        summary: &str,
        payload: Option<&[u8]>,
    ) -> String {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let arrow = match direction {
            Direction::ClientToBackend => "->",
            Direction::BackendToClient => "<-",
        };
        let mut line = format!(
            "{} [{}] {} {} {} {}",
            now, protocol, client, arrow, backend, summary
        );
        if self.include_payload {
            if let Some(data) = payload {
                let snippet = String::from_utf8_lossy(&data[..data.len().min(256)]);
                line.push_str(&format!(" | {}", snippet));
            }
        }
        line
    }
}

impl Default for ProtocolLogFormatter {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_protocol_log_entry_format() {
        let entry = ProtocolLogEntry {
            timestamp: Utc.with_ymd_and_hms(2026, 3, 6, 19, 30, 0).unwrap(),
            client: "10.0.0.1:54321".parse().unwrap(),
            backend: "192.168.1.10:8080".parse().unwrap(),
            bytes_in: 1500,
            bytes_out: 32000,
            duration_secs: 1.234,
        };

        let line = entry.format();
        assert_eq!(
            line,
            "2026-03-06T19:30:00.000Z 10.0.0.1:54321 -> 192.168.1.10:8080 bytes_in=1500 bytes_out=32000 duration=1.234"
        );
    }

    #[test]
    fn test_protocol_log_entry_zero_values() {
        let entry = ProtocolLogEntry {
            timestamp: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            backend: "127.0.0.1:5678".parse().unwrap(),
            bytes_in: 0,
            bytes_out: 0,
            duration_secs: 0.0,
        };

        let line = entry.format();
        assert!(line.contains("bytes_in=0"));
        assert!(line.contains("bytes_out=0"));
        assert!(line.contains("duration=0.000"));
    }
}
