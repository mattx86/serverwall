pub mod command_injection;
pub mod path_traversal;
pub mod protocol_attack;
pub mod sql_injection;
pub mod xss;

pub use command_injection::CommandInjectionDetector;
pub use path_traversal::PathTraversalDetector;
pub use protocol_attack::ProtocolAttackDetector;
pub use sql_injection::SqlInjectionDetector;
pub use xss::XssDetector;

use crate::rules::rule_set::WafRule;

/// Collect all built-in OWASP-style rules.
pub fn all_builtin_rules() -> Vec<WafRule> {
    let mut rules = Vec::new();
    rules.extend(sql_injection::sql_injection_rules());
    rules.extend(xss::xss_rules());
    rules.extend(path_traversal::path_traversal_rules());
    rules.extend(command_injection::command_injection_rules());
    rules.extend(protocol_attack::protocol_attack_rules());
    rules
}
