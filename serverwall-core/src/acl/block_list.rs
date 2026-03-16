use std::net::IpAddr;

use super::matcher::IpMatcher;

/// A block-list of IP addresses/networks.
pub struct BlockList {
    matcher: IpMatcher,
}

impl BlockList {
    /// Create a new block list from CIDR strings.
    pub fn new(cidrs: &[String]) -> Result<Self, ip_network::IpNetworkParseError> {
        Ok(Self {
            matcher: IpMatcher::new(cidrs)?,
        })
    }

    /// Check if the IP is in the block list.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.matcher.matches(ip)
    }
}
