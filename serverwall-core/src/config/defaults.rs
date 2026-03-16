// Default implementations are co-located with their structs in schema.rs
// This module is kept for any future default configuration generation utilities.

use super::schema::ServerWallConfig;

/// Generate a default configuration as a TOML string.
pub fn generate_default_config() -> String {
    let config = ServerWallConfig::default();
    toml::to_string_pretty(&config).unwrap_or_default()
}
