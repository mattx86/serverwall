use std::net::IpAddr;

use super::matcher::IpMatcher;

/// An allow-list of IP addresses/networks.
pub struct AllowList {
    matcher: IpMatcher,
}

impl AllowList {
    /// Create a new allow list from CIDR strings.
    pub fn new(cidrs: &[String]) -> Result<Self, ip_network::IpNetworkParseError> {
        Ok(Self {
            matcher: IpMatcher::new(cidrs)?,
        })
    }

    /// Check if the IP is in the allow list.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.matcher.matches(ip)
    }
}
