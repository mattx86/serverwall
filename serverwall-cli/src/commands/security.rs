use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::schema::{
    BotDetectionConfig, CookieSecurityConfig, GeoConfig, PathPatternConfig, RateLimitConfig,
    SecurityHeadersConfig, SecurityTlsConfig,
};

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct SecurityArgs {
    #[command(subcommand)]
    pub action: SecurityAction,
}

#[derive(Subcommand)]
pub enum SecurityAction {
    /// Show all security settings.
    Show,
    /// Update TLS policy settings.
    SetTls {
        /// Minimum TLS version: tls1.2 or tls1.3.
        #[arg(long)]
        min_version: Option<String>,
        /// Enable OCSP stapling.
        #[arg(long)]
        ocsp_stapling: Option<bool>,
        /// HSTS max-age in seconds (0 = disable HSTS).
        #[arg(long)]
        hsts_max_age: Option<u64>,
        /// Include subdomains in HSTS header.
        #[arg(long)]
        hsts_include_subdomains: Option<bool>,
        /// Verify TLS certificates on backend connections.
        #[arg(long)]
        backend_tls_verify: Option<bool>,
        /// Path to CA bundle for backend TLS verification.
        #[arg(long)]
        backend_ca_bundle: Option<String>,
    },
    /// Update GeoIP settings.
    SetGeo {
        /// Enable GeoIP filtering.
        #[arg(long)]
        enabled: Option<bool>,
        /// Path to MaxMind GeoLite2 or GeoIP2 database file.
        #[arg(long)]
        database_path: Option<String>,
        /// Comma-separated list of 2-letter country codes to block.
        #[arg(long, value_delimiter = ',')]
        block_countries: Option<Vec<String>>,
        /// Comma-separated list of 2-letter country codes to allow (overrides block list).
        #[arg(long, value_delimiter = ',')]
        allow_countries: Option<Vec<String>>,
    },
    /// Update bot detection settings.
    SetBot {
        /// Enable bot detection.
        #[arg(long)]
        enabled: Option<bool>,
        /// Challenge requests from suspicious user agents.
        #[arg(long)]
        challenge_suspicious: Option<bool>,
        /// Verify known-good bot ownership via rDNS.
        #[arg(long)]
        verify_good_bots: Option<bool>,
    },
    /// Update cookie security settings.
    SetCookies {
        /// Enforce Secure flag on all cookies.
        #[arg(long)]
        enforce_secure: Option<bool>,
        /// Enforce HttpOnly flag on all cookies.
        #[arg(long)]
        enforce_httponly: Option<bool>,
        /// Enforce SameSite attribute (Strict, Lax, or None).
        #[arg(long)]
        enforce_samesite: Option<String>,
        /// Maximum cookie size in bytes.
        #[arg(long)]
        max_cookie_size: Option<usize>,
    },
    /// Update HTTP security headers settings.
    SetHeaders {
        /// Add X-Content-Type-Options: nosniff header.
        #[arg(long)]
        x_content_type_options: Option<bool>,
        /// X-Frame-Options value (DENY, SAMEORIGIN, or empty to remove).
        #[arg(long)]
        x_frame_options: Option<String>,
        /// Referrer-Policy value (or empty to remove).
        #[arg(long)]
        referrer_policy: Option<String>,
        /// Content-Security-Policy value (or empty to remove).
        #[arg(long)]
        csp: Option<String>,
        /// Remove Server header from responses.
        #[arg(long)]
        remove_server: Option<bool>,
        /// Remove X-Powered-By header from responses.
        #[arg(long)]
        remove_powered_by: Option<bool>,
        /// Compress responses with gzip.
        #[arg(long)]
        compress_responses: Option<bool>,
        /// Minimum response size in bytes before compression is applied.
        #[arg(long)]
        compress_min_size: Option<usize>,
        /// Comma-separated Content-Type prefixes to compress.
        #[arg(long, value_delimiter = ',')]
        compress_types: Option<Vec<String>>,
    },
    /// Add a global rate limit rule.
    AddRateLimit {
        /// Rule name (unique identifier).
        name: String,
        /// Rate limit key: ip, header:X-Api-Key, etc.
        #[arg(long, default_value = "ip")]
        key: String,
        /// Number of requests allowed.
        #[arg(long)]
        requests: u64,
        /// Time window in seconds.
        #[arg(long)]
        window_secs: u64,
        /// Optional burst allowance.
        #[arg(long)]
        burst: Option<u64>,
    },
    /// Remove a global rate limit rule by name.
    RemoveRateLimit {
        /// Rule name to remove.
        name: String,
    },
    /// List global rate limit rules.
    ListRateLimits,
    /// Update global ACL settings (default action and WAF bypass flag).
    SetAcl {
        /// Default action for unmatched traffic: allow or deny.
        #[arg(long)]
        default_action: Option<String>,
        /// Allow ACL-allowed IPs to bypass WAF checks.
        #[arg(long)]
        bypass_waf: Option<bool>,
    },
    /// Add an IP or CIDR to the global ACL allow list.
    AddIpAllow {
        /// IP address or CIDR block to allow (e.g. 10.0.0.0/8).
        ip: String,
    },
    /// Add an IP or CIDR to the global ACL block list.
    AddIpBlock {
        /// IP address or CIDR block to block (e.g. 203.0.113.0/24).
        ip: String,
    },
    /// Remove an IP or CIDR from either ACL list (allow and block).
    RemoveIp {
        /// IP address or CIDR block to remove.
        ip: String,
    },
    /// Add a domain to the global ACL allow list.
    AddDomainAllow {
        /// Domain or glob pattern to allow.
        domain: String,
    },
    /// Remove a domain from the global ACL allow list.
    RemoveDomainAllow {
        /// Domain to remove.
        domain: String,
    },
    /// Add a domain to the global ACL block list.
    AddDomainBlock {
        /// Domain or glob pattern to block.
        domain: String,
    },
    /// Remove a domain from the global ACL block list.
    RemoveDomainBlock {
        /// Domain to remove.
        domain: String,
    },
    /// Add a path pattern rule to the global ACL.
    AddPathPattern {
        /// Action: allow or deny.
        action: String,
        /// URL path patterns (space-separated, supports globs).
        #[arg(required = true, num_args = 1..)]
        patterns: Vec<String>,
    },
    /// Remove all path pattern rules matching the given action+pattern combination.
    RemovePathPattern {
        /// Action to match (allow or deny).
        action: String,
        /// First pattern to match for removal.
        pattern: String,
    },
}

pub fn run(config_path: &Path, args: SecurityArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        SecurityAction::Show => {
            let config = load_config(config_path)?;
            let s = &config.security;
            println!("=== TLS Policy ===");
            println!("  Min Version:          {}", s.tls.min_version);
            println!("  OCSP Stapling:        {}", s.tls.ocsp_stapling);
            println!("  HSTS Max Age:         {}", s.tls.hsts_max_age.unwrap_or(0));
            println!("  HSTS Subdomains:      {}", s.tls.hsts_include_subdomains);
            println!("  Backend TLS Verify:   {}", s.tls.backend_tls_verify);
            if let Some(ref b) = s.tls.backend_ca_bundle {
                println!("  Backend CA Bundle:    {}", b.display());
            }
            println!();
            println!("=== ACL ===");
            println!("  Default Action:       {:?}", s.acl.default);
            println!("  Bypass WAF:           {}", s.acl.acl_bypass_waf);
            println!("  IP Allow:             {}", s.acl.ip.allow.join(", "));
            println!("  IP Block:             {}", s.acl.ip.block.join(", "));
            println!("  Domain Allow:         {}", s.acl.domain.allow.join(", "));
            println!("  Domain Block:         {}", s.acl.domain.block.join(", "));
            println!("  Path Patterns:        {}", s.acl.path_patterns.len());
            println!();
            println!("=== GeoIP ===");
            println!("  Enabled:              {}", s.geo.enabled);
            println!("  Block Countries:      {}", s.geo.block_countries.join(", "));
            println!("  Allow Countries:      {}", s.geo.allow_countries.join(", "));
            println!();
            println!("=== Bot Detection ===");
            println!("  Enabled:              {}", s.bot_detection.enabled);
            println!("  Challenge Suspicious: {}", s.bot_detection.challenge_suspicious);
            println!("  Verify Good Bots:     {}", s.bot_detection.verify_good_bots);
            println!();
            println!("=== Headers ===");
            println!("  X-Content-Type-Opt:   {}", s.headers.add_x_content_type_options);
            println!("  X-Frame-Options:      {}", s.headers.add_x_frame_options.as_deref().unwrap_or("(off)"));
            println!("  Referrer-Policy:      {}", s.headers.add_referrer_policy.as_deref().unwrap_or("(off)"));
            println!("  Remove Server:        {}", s.headers.remove_server_header);
            println!("  Remove X-Powered-By:  {}", s.headers.remove_x_powered_by);
            println!("  Compress Responses:   {}", s.headers.compress_responses);
            println!("  Compress Min Size:    {} bytes", s.headers.compress_min_size);
            println!();
            println!("=== Cookies ===");
            println!("  Enforce Secure:       {}", s.cookies.enforce_secure_flag);
            println!("  Enforce HttpOnly:     {}", s.cookies.enforce_httponly_flag);
            println!("  Enforce SameSite:     {}", s.cookies.enforce_samesite.as_deref().unwrap_or("(off)"));
            println!("  Max Cookie Size:      {} bytes", s.cookies.max_cookie_size);
            println!();
            if !s.rate_limit.is_empty() {
                println!("=== Rate Limits ===");
                let rows: Vec<Vec<String>> = s.rate_limit.iter().map(|r| vec![
                    r.name.clone(),
                    r.key.clone(),
                    r.requests.to_string(),
                    r.window_secs.to_string(),
                ]).collect();
                output::print_table(&["NAME", "KEY", "REQUESTS", "WINDOW(s)"], &rows);
            }
        }

        SecurityAction::SetTls {
            min_version, ocsp_stapling, hsts_max_age, hsts_include_subdomains,
            backend_tls_verify, backend_ca_bundle,
        } => {
            let config = load_config(config_path)?;
            let mut tls: SecurityTlsConfig = config.security.tls.clone();
            if let Some(v) = min_version              { tls.min_version = v; }
            if let Some(v) = ocsp_stapling            { tls.ocsp_stapling = v; }
            if let Some(v) = hsts_max_age             { tls.hsts_max_age = if v == 0 { None } else { Some(v) }; }
            if let Some(v) = hsts_include_subdomains  { tls.hsts_include_subdomains = v; }
            if let Some(v) = backend_tls_verify       { tls.backend_tls_verify = v; }
            tls.backend_ca_bundle = match backend_ca_bundle {
                Some(ref s) if s.is_empty() => None,
                Some(s) => Some(s.into()),
                None => tls.backend_ca_bundle,
            };
            editor::update_security_tls(config_path, tls)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("TLS settings updated.");
            maybe_reload(no_reload);
        }

        SecurityAction::SetGeo { enabled, database_path, block_countries, allow_countries } => {
            let config = load_config(config_path)?;
            let mut geo: GeoConfig = config.security.geo.clone();
            if let Some(v) = enabled          { geo.enabled = v; }
            if let Some(v) = block_countries  { geo.block_countries = v; }
            if let Some(v) = allow_countries  { geo.allow_countries = v; }
            geo.database_path = match database_path {
                Some(ref s) if s.is_empty() => None,
                Some(s) => Some(s.into()),
                None => geo.database_path,
            };
            editor::update_security_geo(config_path, geo)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("GeoIP settings updated.");
            maybe_reload(no_reload);
        }

        SecurityAction::SetBot { enabled, challenge_suspicious, verify_good_bots } => {
            let config = load_config(config_path)?;
            let mut bot: BotDetectionConfig = config.security.bot_detection.clone();
            if let Some(v) = enabled               { bot.enabled = v; }
            if let Some(v) = challenge_suspicious  { bot.challenge_suspicious = v; }
            if let Some(v) = verify_good_bots      { bot.verify_good_bots = v; }
            editor::update_security_bot(config_path, bot)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Bot detection settings updated.");
            maybe_reload(no_reload);
        }

        SecurityAction::SetCookies { enforce_secure, enforce_httponly, enforce_samesite, max_cookie_size } => {
            let config = load_config(config_path)?;
            let mut cookies: CookieSecurityConfig = config.security.cookies.clone();
            if let Some(v) = enforce_secure   { cookies.enforce_secure_flag = v; }
            if let Some(v) = enforce_httponly { cookies.enforce_httponly_flag = v; }
            if let Some(v) = max_cookie_size  { cookies.max_cookie_size = v; }
            cookies.enforce_samesite = match enforce_samesite {
                Some(ref s) if s.is_empty() => None,
                Some(s) => Some(s),
                None => cookies.enforce_samesite,
            };
            editor::update_security_cookies(config_path, cookies)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Cookie security settings updated.");
            maybe_reload(no_reload);
        }

        SecurityAction::SetHeaders {
            x_content_type_options, x_frame_options, referrer_policy, csp,
            remove_server, remove_powered_by, compress_responses,
            compress_min_size, compress_types,
        } => {
            let config = load_config(config_path)?;
            let mut h: SecurityHeadersConfig = config.security.headers.clone();
            if let Some(v) = x_content_type_options { h.add_x_content_type_options = v; }
            if let Some(v) = remove_server          { h.remove_server_header = v; }
            if let Some(v) = remove_powered_by      { h.remove_x_powered_by = v; }
            if let Some(v) = compress_responses     { h.compress_responses = v; }
            if let Some(v) = compress_min_size      { h.compress_min_size = v; }
            if let Some(v) = compress_types         { h.compress_types = v; }
            h.add_x_frame_options = match x_frame_options {
                Some(ref s) if s.is_empty() => None,
                Some(s) => Some(s),
                None => h.add_x_frame_options,
            };
            h.add_referrer_policy = match referrer_policy {
                Some(ref s) if s.is_empty() => None,
                Some(s) => Some(s),
                None => h.add_referrer_policy,
            };
            h.add_content_security_policy = match csp {
                Some(ref s) if s.is_empty() => None,
                Some(s) => Some(s),
                None => h.add_content_security_policy,
            };
            editor::update_security_headers(config_path, h)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Security headers settings updated.");
            maybe_reload(no_reload);
        }

        SecurityAction::AddRateLimit { name, key, requests, window_secs, burst } => {
            let rule = RateLimitConfig { name: name.clone(), key, requests, window_secs, burst, scope: None };
            editor::add_security_rate_limit(config_path, rule)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Rate limit rule '{}' added.", name);
            maybe_reload(no_reload);
        }

        SecurityAction::RemoveRateLimit { name } => {
            editor::remove_security_rate_limit(config_path, &name)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Rate limit rule '{}' removed.", name);
            maybe_reload(no_reload);
        }

        SecurityAction::ListRateLimits => {
            let config = load_config(config_path)?;
            if config.security.rate_limit.is_empty() {
                println!("No rate limit rules configured.");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = config.security.rate_limit.iter().map(|r| vec![
                r.name.clone(),
                r.key.clone(),
                r.requests.to_string(),
                r.window_secs.to_string(),
                r.burst.map(|b| b.to_string()).unwrap_or_else(|| "-".into()),
            ]).collect();
            output::print_table(&["NAME", "KEY", "REQUESTS", "WINDOW(s)", "BURST"], &rows);
        }

        SecurityAction::SetAcl { default_action, bypass_waf } => {
            let config = load_config(config_path)?;
            let mut acl = config.security.acl.clone();
            if let Some(v) = default_action {
                acl.default = parse_acl_action(&v)?;
            }
            if let Some(v) = bypass_waf { acl.acl_bypass_waf = v; }
            editor::update_security_acl(config_path, acl)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("ACL settings updated.");
            maybe_reload(no_reload);
        }

        SecurityAction::AddIpAllow { ip } => {
            editor::add_acl_allow(config_path, &ip)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("'{}' added to IP allow list.", ip);
            maybe_reload(no_reload);
        }

        SecurityAction::AddIpBlock { ip } => {
            editor::add_acl_block(config_path, &ip)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("'{}' added to IP block list.", ip);
            maybe_reload(no_reload);
        }

        SecurityAction::RemoveIp { ip } => {
            editor::remove_acl_ip(config_path, &ip)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("'{}' removed from IP ACL lists.", ip);
            maybe_reload(no_reload);
        }

        SecurityAction::AddDomainAllow { domain } => {
            let config = load_config(config_path)?;
            let mut acl = config.security.acl.clone();
            if !acl.domain.allow.contains(&domain) {
                acl.domain.allow.push(domain.clone());
            } else {
                println!("'{}' already in domain allow list.", domain);
                return Ok(());
            }
            editor::update_security_acl(config_path, acl)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("'{}' added to domain allow list.", domain);
            maybe_reload(no_reload);
        }

        SecurityAction::RemoveDomainAllow { domain } => {
            let config = load_config(config_path)?;
            let mut acl = config.security.acl.clone();
            let before = acl.domain.allow.len();
            acl.domain.allow.retain(|d| d != &domain);
            if acl.domain.allow.len() == before {
                anyhow::bail!("'{}' not found in domain allow list.", domain);
            }
            editor::update_security_acl(config_path, acl)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("'{}' removed from domain allow list.", domain);
            maybe_reload(no_reload);
        }

        SecurityAction::AddDomainBlock { domain } => {
            let config = load_config(config_path)?;
            let mut acl = config.security.acl.clone();
            if !acl.domain.block.contains(&domain) {
                acl.domain.block.push(domain.clone());
            } else {
                println!("'{}' already in domain block list.", domain);
                return Ok(());
            }
            editor::update_security_acl(config_path, acl)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("'{}' added to domain block list.", domain);
            maybe_reload(no_reload);
        }

        SecurityAction::RemoveDomainBlock { domain } => {
            let config = load_config(config_path)?;
            let mut acl = config.security.acl.clone();
            let before = acl.domain.block.len();
            acl.domain.block.retain(|d| d != &domain);
            if acl.domain.block.len() == before {
                anyhow::bail!("'{}' not found in domain block list.", domain);
            }
            editor::update_security_acl(config_path, acl)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("'{}' removed from domain block list.", domain);
            maybe_reload(no_reload);
        }

        SecurityAction::AddPathPattern { action, patterns } => {
            let config = load_config(config_path)?;
            let mut acl = config.security.acl.clone();
            acl.path_patterns.push(PathPatternConfig { action: action.clone(), patterns: patterns.clone() });
            editor::update_security_acl(config_path, acl)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Path pattern rule ({} {}) added.", action, patterns.join(", "));
            maybe_reload(no_reload);
        }

        SecurityAction::RemovePathPattern { action, pattern } => {
            let config = load_config(config_path)?;
            let mut acl = config.security.acl.clone();
            let before = acl.path_patterns.len();
            acl.path_patterns.retain(|p| !(p.action == action && p.patterns.contains(&pattern)));
            if acl.path_patterns.len() == before {
                anyhow::bail!("No path pattern rule matching action='{}' pattern='{}' found.", action, pattern);
            }
            editor::update_security_acl(config_path, acl)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Path pattern rule removed.");
            maybe_reload(no_reload);
        }
    }
    Ok(())
}

fn parse_acl_action(s: &str) -> anyhow::Result<serverwall_core::config::schema::AclDefaultAction> {
    use serverwall_core::config::schema::AclDefaultAction;
    match s.to_lowercase().as_str() {
        "allow" => Ok(AclDefaultAction::Allow),
        "deny"  => Ok(AclDefaultAction::Deny),
        _ => anyhow::bail!("invalid ACL action '{}'; use: allow, deny", s),
    }
}
