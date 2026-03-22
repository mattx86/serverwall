pub mod allow_list;
pub mod block_list;
pub mod geo;
pub mod matcher;

pub use allow_list::AllowList;
pub use block_list::BlockList;
pub use geo::GeoEngine;
pub use matcher::IpMatcher;

use std::net::IpAddr;

use regex::Regex;

use crate::config::schema::{AclDefaultAction, FrontendAclConfig, PathPatternConfig};

/// Result of an ACL evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    Allow,
    Deny,
}

/// Access control engine that evaluates allow/block rules.
///
/// Evaluation order:
/// 1. If the IP matches the block list, deny immediately.
/// 2. If an allow list is configured and non-empty, the IP must be in it.
/// 3. Otherwise, fall back to the configured default action.
pub struct AccessControlEngine {
    block_list: Option<BlockList>,
    allow_list: Option<AllowList>,
    default_action: AclDefaultAction,
}

impl AccessControlEngine {
    /// Create an access control engine from a `FrontendAclConfig`.
    pub fn from_config(config: &FrontendAclConfig) -> Result<Self, ip_network::IpNetworkParseError> {
        let block_list = if config.block_list.is_empty() {
            None
        } else {
            Some(BlockList::new(&config.block_list)?)
        };

        let allow_list = if config.allow_list.is_empty() {
            None
        } else {
            Some(AllowList::new(&config.allow_list)?)
        };

        Ok(Self {
            block_list,
            allow_list,
            default_action: config.default_action,
        })
    }

    /// Create a new access control engine with explicit components.
    pub fn new(
        allow_list: Option<AllowList>,
        block_list: Option<BlockList>,
        default_action: AclDefaultAction,
    ) -> Self {
        Self {
            block_list,
            allow_list,
            default_action,
        }
    }

    /// Evaluate whether a given IP address is permitted.
    pub fn evaluate(&self, ip: IpAddr) -> AclDecision {
        // Step 1: Block list takes priority.
        if let Some(ref bl) = self.block_list {
            if bl.contains(ip) {
                return AclDecision::Deny;
            }
        }

        // Step 2: If an allow list is configured, the IP must be in it.
        if let Some(ref al) = self.allow_list {
            return if al.contains(ip) {
                AclDecision::Allow
            } else {
                AclDecision::Deny
            };
        }

        // Step 3: Fall back to default action.
        match self.default_action {
            AclDefaultAction::Allow => AclDecision::Allow,
            AclDefaultAction::Deny => AclDecision::Deny,
        }
    }

    /// Convenience method: returns true if the IP is allowed.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        self.evaluate(ip) == AclDecision::Allow
    }
}

// =============================================================================
// Path ACL
// =============================================================================

/// A path-based access control check.
///
/// Each rule contains one or more URL-path regex patterns and an associated
/// action.  Patterns are tested against the request path in order; the first
/// match wins.
pub struct PathAcl {
    /// (compiled patterns for a rule, should_block)
    rules: Vec<(Vec<Regex>, bool)>,
}

impl PathAcl {
    /// Build a `PathAcl` from the configured `[security.acl] path_patterns`.
    ///
    /// Invalid regex patterns are logged and skipped.
    pub fn from_config(patterns: &[PathPatternConfig]) -> Self {
        let mut rules = Vec::new();
        for entry in patterns {
            let block = entry.action.to_lowercase() == "block";
            let mut compiled = Vec::new();
            for raw in &entry.patterns {
                match Regex::new(raw) {
                    Ok(re) => compiled.push(re),
                    Err(e) => tracing::warn!(pattern = %raw, error = %e, "invalid path ACL regex, skipping"),
                }
            }
            if !compiled.is_empty() {
                rules.push((compiled, block));
            }
        }
        Self { rules }
    }

    /// Check a request path.
    ///
    /// Returns `Some(AclDecision::Deny)` if a blocking rule matches,
    /// `Some(AclDecision::Allow)` if an allow rule matches, or `None` if no
    /// rule matches (caller falls through to the default).
    pub fn check(&self, path: &str) -> Option<AclDecision> {
        for (patterns, block) in &self.rules {
            if patterns.iter().any(|re| re.is_match(path)) {
                return Some(if *block {
                    AclDecision::Deny
                } else {
                    AclDecision::Allow
                });
            }
        }
        None
    }

    /// Returns `true` if there are no path rules configured.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_config_allows_all() {
        let config = FrontendAclConfig::default();
        let engine = AccessControlEngine::from_config(&config).unwrap();

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(engine.evaluate(ip), AclDecision::Allow);
        assert!(engine.is_allowed(ip));
    }

    #[test]
    fn test_block_list_denies_matching_ip() {
        let config = FrontendAclConfig {
            block_list: vec!["10.0.0.0/8".to_string()],
            allow_list: vec![],
            default_action: AclDefaultAction::Allow,
        };
        let engine = AccessControlEngine::from_config(&config).unwrap();

        assert_eq!(engine.evaluate("10.1.2.3".parse().unwrap()), AclDecision::Deny);
        assert_eq!(engine.evaluate("192.168.1.1".parse().unwrap()), AclDecision::Allow);
    }

    #[test]
    fn test_allow_list_restricts_to_listed() {
        let config = FrontendAclConfig {
            block_list: vec![],
            allow_list: vec!["192.168.1.0/24".to_string()],
            default_action: AclDefaultAction::Allow,
        };
        let engine = AccessControlEngine::from_config(&config).unwrap();

        assert_eq!(engine.evaluate("192.168.1.50".parse().unwrap()), AclDecision::Allow);
        assert_eq!(engine.evaluate("10.0.0.1".parse().unwrap()), AclDecision::Deny);
    }

    #[test]
    fn test_block_list_takes_priority_over_allow_list() {
        let config = FrontendAclConfig {
            block_list: vec!["192.168.1.100/32".to_string()],
            allow_list: vec!["192.168.1.0/24".to_string()],
            default_action: AclDefaultAction::Allow,
        };
        let engine = AccessControlEngine::from_config(&config).unwrap();

        // 192.168.1.100 is in both lists; block list wins
        assert_eq!(engine.evaluate("192.168.1.100".parse().unwrap()), AclDecision::Deny);
        // 192.168.1.50 is only in allow list
        assert_eq!(engine.evaluate("192.168.1.50".parse().unwrap()), AclDecision::Allow);
        // 10.0.0.1 is in neither; since allow list exists, it's denied
        assert_eq!(engine.evaluate("10.0.0.1".parse().unwrap()), AclDecision::Deny);
    }

    #[test]
    fn test_default_action_deny() {
        let config = FrontendAclConfig {
            block_list: vec![],
            allow_list: vec![],
            default_action: AclDefaultAction::Deny,
        };
        let engine = AccessControlEngine::from_config(&config).unwrap();

        assert_eq!(engine.evaluate("1.2.3.4".parse().unwrap()), AclDecision::Deny);
        assert!(!engine.is_allowed("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_single_ip_in_block_list() {
        let config = FrontendAclConfig {
            block_list: vec!["203.0.113.5/32".to_string()],
            allow_list: vec![],
            default_action: AclDefaultAction::Allow,
        };
        let engine = AccessControlEngine::from_config(&config).unwrap();

        assert_eq!(engine.evaluate("203.0.113.5".parse().unwrap()), AclDecision::Deny);
        assert_eq!(engine.evaluate("203.0.113.6".parse().unwrap()), AclDecision::Allow);
    }

    #[test]
    fn test_ipv6_support() {
        let config = FrontendAclConfig {
            block_list: vec!["fd00::/8".to_string()],
            allow_list: vec![],
            default_action: AclDefaultAction::Allow,
        };
        let engine = AccessControlEngine::from_config(&config).unwrap();

        assert_eq!(engine.evaluate("fd00::1".parse().unwrap()), AclDecision::Deny);
        assert_eq!(engine.evaluate("2001:db8::1".parse().unwrap()), AclDecision::Allow);
    }
}
