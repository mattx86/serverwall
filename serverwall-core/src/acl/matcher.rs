use std::net::IpAddr;

use ip_network::IpNetwork;

/// Matches IP addresses against a set of CIDR networks.
#[derive(Debug, Clone)]
pub struct IpMatcher {
    networks: Vec<IpNetwork>,
}

impl IpMatcher {
    /// Create a new matcher from a list of CIDR strings.
    pub fn new(cidrs: &[String]) -> Result<Self, ip_network::IpNetworkParseError> {
        let mut networks = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            let net: IpNetwork = cidr.parse()?;
            networks.push(net);
        }
        Ok(Self { networks })
    }

    /// Check if the given IP matches any network in this matcher.
    pub fn matches(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(ip))
    }

    /// Returns the number of networks in the matcher.
    pub fn len(&self) -> usize {
        self.networks.len()
    }

    /// Returns true if no networks are configured.
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }
}
