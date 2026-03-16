pub mod types;
pub mod error;
pub mod config;
pub mod tls;
pub mod balancer;
pub mod health;
pub mod acl;
pub mod logging;
pub mod proto;

/// Default path to the serverwall configuration file.
pub const DEFAULT_CONFIG_PATH: &str = "/opt/serverwall/etc/serverwall.toml";

/// Default path to the serverwall PID file.
pub const DEFAULT_PID_FILE: &str = "/opt/serverwall/run/serverwall.pid";

pub use config::send_reload_signal;
