use std::net::IpAddr;

use ip_network::IpNetwork;
use serverwall_core::config::schema::TrustedHostsConfig;

/// Parsed IP/CIDR allowlist for trusted internal hosts.
pub struct TrustedHosts {
    networks: Vec<IpNetwork>,
    single_ips: Vec<IpAddr>,
    /// When true, plain-text connections from trusted hosts are rejected with 530.
    pub require_tls: bool,
}

impl TrustedHosts {
    /// Parse the trusted hosts configuration into network/IP entries.
    pub fn new(config: &TrustedHostsConfig) -> Self {
        let mut networks = Vec::new();
        let mut single_ips = Vec::new();

        for entry in &config.hosts {
            let trimmed = entry.trim();
            // Try parsing as CIDR notation first
            if let Ok(network) = trimmed.parse::<IpNetwork>() {
                networks.push(network);
            } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
                single_ips.push(ip);
            } else {
                tracing::warn!(entry = %trimmed, "ignoring unparseable trusted_hosts entry");
            }
        }

        Self { networks, single_ips, require_tls: config.require_tls }
    }

    /// Check whether the given IP address is in the allowlist.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        // Check single IPs
        if self.single_ips.contains(&ip) {
            return true;
        }

        // Check CIDR networks
        for network in &self.networks {
            if network.contains(ip) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from(hosts: &[&str]) -> TrustedHostsConfig {
        TrustedHostsConfig {
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            require_tls: false,
        }
    }

    #[test]
    fn test_single_ip() {
        let th = TrustedHosts::new(&config_from(&["10.0.0.1"]));
        assert!(th.is_trusted("10.0.0.1".parse().unwrap()));
        assert!(!th.is_trusted("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_cidr() {
        let th = TrustedHosts::new(&config_from(&["10.0.0.0/8"]));
        assert!(th.is_trusted("10.0.0.1".parse().unwrap()));
        assert!(th.is_trusted("10.255.255.255".parse().unwrap()));
        assert!(!th.is_trusted("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_multiple_entries() {
        let th = TrustedHosts::new(&config_from(&["10.0.0.0/8", "192.168.0.0/16", "172.16.0.1"]));
        assert!(th.is_trusted("10.1.2.3".parse().unwrap()));
        assert!(th.is_trusted("192.168.1.1".parse().unwrap()));
        assert!(th.is_trusted("172.16.0.1".parse().unwrap()));
        assert!(!th.is_trusted("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_empty() {
        let th = TrustedHosts::new(&config_from(&[]));
        assert!(!th.is_trusted("127.0.0.1".parse().unwrap()));
    }
}
