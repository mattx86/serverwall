use serde::{Deserialize, Serialize};

/// Health status of a backend server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendHealth {
    /// Backend is responding normally.
    Healthy,
    /// Backend has intermittent failures; may be transitioning.
    Suspect,
    /// Backend is unreachable or failing health checks.
    Down,
}

impl BackendHealth {
    /// Returns true if the backend should receive traffic.
    pub fn is_available(&self) -> bool {
        matches!(self, BackendHealth::Healthy)
    }
}

impl std::fmt::Display for BackendHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendHealth::Healthy => write!(f, "healthy"),
            BackendHealth::Suspect => write!(f, "suspect"),
            BackendHealth::Down => write!(f, "down"),
        }
    }
}
