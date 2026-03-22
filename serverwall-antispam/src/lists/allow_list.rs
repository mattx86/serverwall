use std::collections::HashSet;
use std::net::IpAddr;

/// A set of trusted senders, domains, or IPs that bypass spam checks.
pub struct AllowList {
    pub ips: HashSet<String>,
    pub senders: HashSet<String>,
    pub sender_domains: HashSet<String>,
}

impl AllowList {
    pub fn new() -> Self {
        Self {
            ips: HashSet::new(),
            senders: HashSet::new(),
            sender_domains: HashSet::new(),
        }
    }

    /// Build from config lists.
    pub fn from_config(
        ips: Vec<String>,
        senders: Vec<String>,
        sender_domains: Vec<String>,
    ) -> Self {
        Self {
            ips: ips.into_iter().collect(),
            senders: senders.into_iter().map(|s| s.to_lowercase()).collect(),
            sender_domains: sender_domains.into_iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    /// Check if an IP is in the allow list.
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip.to_string())
    }

    /// Check if a sender address is in the allow list.
    pub fn contains_sender(&self, sender: &str) -> bool {
        self.senders.contains(&sender.to_lowercase())
    }

    /// Check if a sender's domain is in the allow list.
    pub fn contains_domain(&self, sender: &str) -> bool {
        if let Some((_, domain)) = sender.rsplit_once('@') {
            let domain = domain.trim_end_matches('>').to_lowercase();
            self.sender_domains.contains(&domain)
        } else {
            false
        }
    }

    /// Check if any criteria matches.
    pub fn matches(&self, ip: IpAddr, sender: &str) -> bool {
        self.contains_ip(ip)
            || self.contains_sender(sender)
            || self.contains_domain(sender)
    }
}

impl Default for AllowList {
    fn default() -> Self {
        Self::new()
    }
}
