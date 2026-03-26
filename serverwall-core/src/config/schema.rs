use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level configuration for the entire ServerWall instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerWallConfig {
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default, rename = "webui")]
    pub webui: WebuiConfig,
    #[serde(default)]
    pub acme: AcmeConfig,
    #[serde(default)]
    pub frontend: Vec<FrontendConfig>,
    #[serde(default)]
    pub backend_pool: Vec<BackendPoolConfig>,
    #[serde(default)]
    pub waf_ruleset: Vec<WafRulesetConfig>,
    #[serde(default)]
    pub security_profiles: Vec<SecurityProfile>,
    #[serde(default)]
    pub log_profiles: Vec<LogProfile>,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub antispam: AntispamConfig,
    #[serde(default)]
    pub relay: RelayConfig,
}

// =============================================================================
// Global
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_daemon_name")]
    pub daemon_name: String,
    #[serde(default)]
    pub pid_file: Option<PathBuf>,
    #[serde(default)]
    pub worker_threads: usize, // 0 = auto-detect
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,
    #[serde(default)]
    pub config_dir: Option<PathBuf>, // conf.d/ drop-in directory
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Seconds to wait for active connections to drain on graceful shutdown (SIGTERM).
    /// 0 = disable drain (exit immediately). Default: 30.
    #[serde(default = "default_drain_timeout")]
    pub graceful_drain_secs: u64,
}

// =============================================================================
// Web UI
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebuiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_webui_listen")]
    pub listen: String,
    #[serde(default = "default_webui_cert")]
    pub tls_cert: Option<PathBuf>,
    #[serde(default = "default_webui_key")]
    pub tls_key: Option<PathBuf>,
    #[serde(default = "default_tokens_file")]
    pub tokens_file: PathBuf,
    #[serde(default = "default_web_users_file")]
    pub web_users_file: PathBuf,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_webui_allow_list")]
    pub allow_list: Vec<String>,
}

// =============================================================================
// ACME / Let's Encrypt
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    #[serde(default = "default_acme_challenge")]
    pub challenge_type: String,
    #[serde(default = "default_acme_storage")]
    pub storage_dir: PathBuf,
    #[serde(default = "default_true")]
    pub auto_renew: bool,
    #[serde(default = "default_renew_days")]
    pub renew_before_days: u32,
    /// CIDR ranges allowed to reach the HTTP-01 challenge server on the challenge port.
    /// Defaults to Let's Encrypt's known validation IPs.  Set to an empty list to allow all.
    /// See https://letsencrypt.org/docs/faq/ for the current list (including multi-perspective
    /// vantage points); add any additional ranges required by your ACME provider.
    #[serde(default = "default_acme_allowed_cidrs")]
    pub challenge_allowed_cidrs: Vec<String>,
}

// =============================================================================
// Frontend
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontendConfig {
    pub name: String,
    pub protocol: ProtocolType,
    pub listen: Vec<String>,
    pub backend_pool: String,

    // TLS - Style 1: Combined PEM
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    // TLS - Style 2: Separate files
    #[serde(default)]
    pub tls_chain: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    #[serde(default)]
    pub tls_key_password: Option<String>,
    // TLS - Style 3: PKCS#12/PFX
    #[serde(default)]
    pub tls_pfx: Option<PathBuf>,
    #[serde(default)]
    pub tls_pfx_password: Option<String>,

    #[serde(default = "default_tls_min_version")]
    pub tls_min_version: String,
    #[serde(default)]
    pub tls_ciphers: Vec<String>,

    #[serde(default = "default_balance_method")]
    pub balancer: BalanceMethod,

    // WAF (HTTPS only)
    #[serde(default)]
    pub waf_enabled: bool,
    #[serde(default)]
    pub waf_ruleset: Option<String>,
    #[serde(default)]
    pub security_profile: Option<String>,

    // Logging
    #[serde(default)]
    pub log_file: Option<String>,
    #[serde(default = "default_log_format")]
    pub log_format: LogFormat,
    #[serde(default = "default_true")]
    pub access_log: bool,
    #[serde(default)]
    pub log_profile: Option<String>,

    // Headers (HTTP/SMTP)
    #[serde(default)]
    pub headers: FrontendHeadersConfig,
    #[serde(default)]
    pub smtp_headers: SmtpHeadersConfig,

    // ACL
    #[serde(default)]
    pub acl: FrontendAclConfig,

    // Connection limits
    #[serde(default)]
    pub max_connections: Option<usize>,

    /// Cookie name used for sticky-session routing. Defaults to `_s`.
    #[serde(default = "default_session_cookie")]
    pub session_cookie: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FrontendHeadersConfig {
    #[serde(default = "default_true")]
    pub x_forwarded_for: bool,
    #[serde(default = "default_true")]
    pub x_real_ip: bool,
    #[serde(default = "default_true")]
    pub x_forwarded_proto: bool,
    #[serde(default)]
    pub x_forwarded_host: bool,
    #[serde(default)]
    pub x_forwarded_port: bool,
    #[serde(default)]
    pub x_request_id: bool,
    #[serde(default)]
    pub custom: Vec<CustomHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SmtpHeadersConfig {
    #[serde(default = "default_true")]
    pub add_received: bool,
    #[serde(default)]
    pub x_forwarded_for: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FrontendAclConfig {
    #[serde(default)]
    pub allow_list: Vec<String>,
    #[serde(default)]
    pub block_list: Vec<String>,
    #[serde(default = "default_acl_action")]
    pub default_action: AclDefaultAction,
}

// =============================================================================
// Backend Pool
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendPoolConfig {
    pub name: String,
    #[serde(default = "default_health_interval")]
    pub health_check_interval: String,
    #[serde(default = "default_health_timeout")]
    pub health_check_timeout: String,
    #[serde(default = "default_health_type")]
    pub health_check_type: HealthCheckType,
    #[serde(default)]
    pub health_check_path: Option<String>,
    #[serde(default = "default_health_expect")]
    pub health_check_expect: u16,
    /// Use TLS when performing HTTP, SMTP, or IMAP health checks.
    #[serde(default)]
    pub health_check_tls: bool,
    /// Skip TLS certificate verification in health checks (useful for self-signed certs).
    #[serde(default)]
    pub health_check_ignore_cert: bool,
    /// HTTP method to use for HTTP/HTTPS health checks ("GET" or "POST").
    #[serde(default = "default_health_method")]
    pub health_check_method: String,
    #[serde(default)]
    pub backend: Vec<BackendConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub name: String,
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub tls_verify: Option<bool>,
    #[serde(default)]
    pub tls_sni: Option<String>,
    #[serde(default)]
    pub max_connections: Option<usize>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// =============================================================================
// WAF Rulesets
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRulesetConfig {
    pub name: String,
    #[serde(default = "default_waf_mode")]
    pub mode: WafMode,
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: u32,
    #[serde(default)]
    pub rules_dir: Option<PathBuf>,
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,
    #[serde(default)]
    pub exclusions: WafExclusions,
    #[serde(default)]
    pub custom_rules: Vec<WafCustomRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WafExclusions {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafCustomRule {
    pub id: u64,
    pub description: String,
    #[serde(default = "default_one")]
    pub phase: u8,
    #[serde(default = "default_waf_rule_action")]
    pub action: String,
    pub match_field: String,
    pub operator: String,
    pub pattern: String,
}

// =============================================================================
// Security
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub tls: SecurityTlsConfig,
    #[serde(default)]
    pub acl: SecurityAclConfig,
    #[serde(default)]
    pub rate_limit: Vec<RateLimitConfig>,
    #[serde(default)]
    pub geo: GeoConfig,
    #[serde(default)]
    pub bot_detection: BotDetectionConfig,
    #[serde(default)]
    pub cookies: CookieSecurityConfig,
    #[serde(default)]
    pub headers: SecurityHeadersConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityTlsConfig {
    #[serde(default = "default_tls_min_version")]
    pub min_version: String,
    #[serde(default)]
    pub cipher_suites: Vec<String>,
    #[serde(default)]
    pub ocsp_stapling: bool,
    #[serde(default)]
    pub hsts_max_age: Option<u64>,
    #[serde(default)]
    pub hsts_include_subdomains: bool,
    #[serde(default)]
    pub backend_tls_verify: bool,
    #[serde(default)]
    pub backend_ca_bundle: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityAclConfig {
    #[serde(default = "default_acl_action")]
    pub default: AclDefaultAction,
    #[serde(default)]
    pub acl_bypass_waf: bool,
    #[serde(default)]
    pub ip: IpAclConfig,
    #[serde(default)]
    pub domain: DomainAclConfig,
    #[serde(default)]
    pub path_patterns: Vec<PathPatternConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpAclConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainAclConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPatternConfig {
    pub action: String,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub name: String,
    #[serde(default = "default_rate_key")]
    pub key: String,
    pub requests: u64,
    pub window_secs: u64,
    #[serde(default)]
    pub burst: Option<u64>,
    #[serde(default)]
    pub scope: Option<RateLimitScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitScope {
    #[serde(rename = "type")]
    pub scope_type: String,
    #[serde(default)]
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_geoip_db_path")]
    pub database_path: Option<PathBuf>,
    #[serde(default)]
    pub block_countries: Vec<String>,
    #[serde(default)]
    pub allow_countries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BotDetectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ja3_fingerprint_block_list: Vec<String>,
    #[serde(default)]
    pub challenge_suspicious: bool,
    #[serde(default)]
    pub known_good_bots: Vec<String>,
    #[serde(default)]
    pub verify_good_bots: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CookieSecurityConfig {
    #[serde(default)]
    pub enforce_secure_flag: bool,
    #[serde(default)]
    pub enforce_httponly_flag: bool,
    #[serde(default)]
    pub enforce_samesite: Option<String>,
    #[serde(default = "default_cookie_size")]
    pub max_cookie_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    #[serde(default)]
    pub add_x_content_type_options: bool,
    #[serde(default)]
    pub add_x_frame_options: Option<String>,
    #[serde(default)]
    pub add_referrer_policy: Option<String>,
    #[serde(default)]
    pub add_content_security_policy: Option<String>,
    #[serde(default = "default_true")]
    pub remove_server_header: bool,
    #[serde(default = "default_true")]
    pub remove_x_powered_by: bool,
    /// Compress responses with gzip when the client sends `Accept-Encoding: gzip`.
    #[serde(default)]
    pub compress_responses: bool,
    /// Minimum response body size in bytes before compression is applied.
    #[serde(default = "default_compress_min_size")]
    pub compress_min_size: usize,
    /// `Content-Type` prefixes eligible for compression.
    #[serde(default = "default_compress_types")]
    pub compress_types: Vec<String>,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            add_x_content_type_options: false,
            add_x_frame_options: None,
            add_referrer_policy: None,
            add_content_security_policy: None,
            remove_server_header: true,
            remove_x_powered_by: true,
            compress_responses: false,
            compress_min_size: default_compress_min_size(),
            compress_types: default_compress_types(),
        }
    }
}

/// A named bundle of per-frontend security overrides.
///
/// When a frontend references a security profile, the profile's settings
/// take precedence over the global `[security]` configuration for that frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Protocol type this profile is designed for: `"HTTP"`, `"SMTP"`, `"IMAP"`, or `"TCP"`.
    /// Used by the UI to show/hide relevant settings tabs. Defaults to `"HTTP"`.
    #[serde(default = "default_profile_type")]
    pub profile_type: String,
    #[serde(default)]
    pub waf_enabled: bool,
    #[serde(default)]
    pub waf_ruleset: Option<String>,
    #[serde(default)]
    pub headers: SecurityHeadersConfig,
    #[serde(default)]
    pub cookies: CookieSecurityConfig,
    #[serde(default)]
    pub bot_detection: BotDetectionConfig,
    #[serde(default)]
    pub geo: GeoConfig,
    /// Antispam and antivirus settings for SMTP/SMTPS frontends using this profile.
    /// `None` means SMTP frontends fall back to the global `[antispam]` configuration.
    #[serde(default)]
    pub antispam: Option<SecurityProfileAntispam>,

    // TLS settings — override global security.tls for frontends using this profile.
    #[serde(default = "default_tls_min_version")]
    pub min_version: String,
    #[serde(default)]
    pub cipher_suites: Vec<String>,
    #[serde(default)]
    pub hsts_max_age: Option<u64>,
    #[serde(default)]
    pub hsts_include_subdomains: bool,
    #[serde(default)]
    pub ocsp_stapling: bool,
}

/// Antispam and antivirus overrides for SMTP frontends that reference this security profile.
/// Fields that are `None` (thresholds) fall back to the global antispam configuration.
/// The `antivirus` field completely replaces the global antivirus config when this section is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfileAntispam {
    /// Whether antispam filtering is active for SMTP frontends using this profile.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Override the possible-spam threshold (0–100). `None` = use global.
    #[serde(default)]
    pub possible_spam_threshold: Option<u8>,
    /// Override the definite-spam threshold (0–100). `None` = use global.
    #[serde(default)]
    pub definite_spam_threshold: Option<u8>,
    /// Antivirus scanner configuration for this profile.
    /// Replaces the global antivirus config entirely when this antispam section is present.
    #[serde(default)]
    pub antivirus: AntivirusConfig,
}

/// Named logging profile — groups log format and access-log toggle so they
/// can be shared across multiple frontends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_log_format")]
    pub format: LogFormat,
    #[serde(default = "default_true")]
    pub access_log: bool,
}

// =============================================================================
// Antispam
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AntispamConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_possible_spam")]
    pub possible_spam_threshold: u8,
    #[serde(default = "default_definite_spam")]
    pub definite_spam_threshold: u8,
    #[serde(default = "default_check_duration")]
    pub max_check_duration: String,

    #[serde(default)]
    pub allow: AntispamListConfig,
    #[serde(default)]
    pub block: AntispamListConfig,

    #[serde(default)]
    pub dnsbl: DnsblConfig,
    #[serde(default)]
    pub spf: SpfConfig,
    #[serde(default)]
    pub rdns: CheckWeightConfig,
    #[serde(default)]
    pub residential_spf: ResidentialSenderConfig,
    #[serde(default)]
    pub helo: CheckWeightConfig,
    #[serde(default)]
    pub rate_limit: SmtpRateLimitConfig,
    #[serde(default)]
    pub early_talker: CheckWeightConfig,

    #[serde(default)]
    pub dkim: CheckWeightConfig,
    #[serde(default)]
    pub dmarc: DmarcConfig,
    #[serde(default)]
    pub content: ContentCheckConfig,
    #[serde(default)]
    pub url_analysis: UrlAnalysisConfig,
    #[serde(default)]
    pub attachment: AttachmentConfig,
    #[serde(default)]
    pub html: CheckWeightConfig,
    #[serde(default)]
    pub header_analysis: CheckWeightConfig,
    #[serde(default)]
    pub charset: CheckWeightConfig,
    #[serde(default)]
    pub bulk: CheckWeightConfig,
    #[serde(default)]
    pub ratio: CheckWeightConfig,
    #[serde(default)]
    pub antivirus: AntivirusConfig,

    #[serde(default)]
    pub domain_overrides: Vec<DomainOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AntispamListConfig {
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub sender_domains: Vec<String>,
    #[serde(default)]
    pub senders: Vec<String>,
    #[serde(default)]
    pub recipients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckWeightConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_check_weight")]
    pub weight: f64,
}

impl Default for CheckWeightConfig {
    fn default() -> Self { Self { enabled: true, weight: default_check_weight() } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidentialSenderConfig {
    /// Enable the residential sender SPF enforcement check.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// When true, matching senders are rejected (550). When false, a score penalty is applied instead (useful for testing).
    #[serde(default = "default_true")]
    pub reject: bool,
    /// Score penalty applied when `reject = false`.
    #[serde(default = "default_residential_weight")]
    pub weight: f64,
    /// Query the Spamhaus PBL (or a custom zone) to detect residential IP ranges by ISP policy (IPv4 only).
    #[serde(default = "default_true")]
    pub check_pbl: bool,
    /// DNSBL zone for residential/policy-blocked IP ranges.
    #[serde(default = "default_pbl_zone")]
    pub pbl_zone: String,
    /// Treat SPF SoftFail as a reject trigger (in addition to Fail and None).
    #[serde(default = "default_true")]
    pub softfail_triggers: bool,
    /// Treat SPF Neutral as a reject trigger.
    #[serde(default)]
    pub neutral_triggers: bool,
}

impl Default for ResidentialSenderConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            reject: true,
            weight: default_residential_weight(),
            check_pbl: true,
            pbl_zone: default_pbl_zone(),
            softfail_triggers: true,
            neutral_triggers: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dnsbl_weight")]
    pub weight: f64,
    #[serde(default = "default_dnsbl_timeout")]
    pub timeout: String,
    #[serde(default = "default_dnsbl_lists")]
    pub lists: Vec<DnsblListEntry>,
}

impl Default for DnsblConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            weight: default_dnsbl_weight(),
            timeout: default_dnsbl_timeout(),
            lists: default_dnsbl_lists(),
        }
    }
}

fn default_dnsbl_lists() -> Vec<DnsblListEntry> {
    vec![
        DnsblListEntry { zone: "zen.spamhaus.org".into(),      weight_multiplier: 2.0, reject_on_hit: true  },
        DnsblListEntry { zone: "bl.spamcop.net".into(),        weight_multiplier: 1.0, reject_on_hit: false },
        DnsblListEntry { zone: "b.barracudacentral.org".into(),weight_multiplier: 1.0, reject_on_hit: false },
        DnsblListEntry { zone: "psbl.surriel.com".into(),      weight_multiplier: 0.8, reject_on_hit: false },
        DnsblListEntry { zone: "dnsbl.sorbs.net".into(),       weight_multiplier: 0.8, reject_on_hit: false },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblListEntry {
    pub zone: String,
    #[serde(default = "default_one_f64")]
    pub weight_multiplier: f64,
    #[serde(default)]
    pub reject_on_hit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_spf_weight")]
    pub weight: f64,
    #[serde(default)]
    pub severity: SpfSeverityConfig,
}

impl Default for SpfConfig {
    fn default() -> Self { Self { enabled: true, weight: default_spf_weight(), severity: SpfSeverityConfig::default() } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfSeverityConfig {
    #[serde(default = "default_one_f64")]
    pub fail: f64,
    #[serde(default = "default_half_f64")]
    pub softfail: f64,
    #[serde(default = "default_point_one")]
    pub neutral: f64,
    #[serde(default = "default_point_three")]
    pub none: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SmtpRateLimitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rate_weight")]
    pub weight: f64,
    #[serde(default)]
    pub per_ip: SmtpRateRule,
    #[serde(default)]
    pub per_domain: SmtpRateRule,
    #[serde(default)]
    pub per_sender: SmtpRateRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpRateRule {
    #[serde(default = "default_rate_max")]
    pub max: u64,
    #[serde(default = "default_rate_window")]
    pub window: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dmarc_weight")]
    pub weight: f64,
    #[serde(default = "default_true")]
    pub honor_reject_policy: bool,
}

impl Default for DmarcConfig {
    fn default() -> Self { Self { enabled: true, weight: default_dmarc_weight(), honor_reject_policy: true } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentCheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_content_weight")]
    pub weight: f64,
    #[serde(default)]
    pub rules_file: Option<String>,
}

impl Default for ContentCheckConfig {
    fn default() -> Self { Self { enabled: true, weight: default_content_weight(), rules_file: None } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlAnalysisConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_url_weight")]
    pub weight: f64,
    #[serde(default)]
    pub surbl_zones: Vec<String>,
}

impl Default for UrlAnalysisConfig {
    fn default() -> Self { Self { enabled: true, weight: default_url_weight(), surbl_zones: Vec::new() } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_attachment_weight")]
    pub weight: f64,
    #[serde(default = "default_dangerous_extensions")]
    pub dangerous_extensions: Vec<String>,
}

impl Default for AttachmentConfig {
    fn default() -> Self { Self { enabled: true, weight: default_attachment_weight(), dangerous_extensions: default_dangerous_extensions() } }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AntivirusConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_av_weight")]
    pub weight: f64,
    #[serde(default = "default_true")]
    pub reject_on_virus: bool,
    #[serde(default)]
    pub scanners: Vec<ScannerConfig>,
    #[serde(default = "default_av_error_action")]
    pub on_scanner_error: String,
    #[serde(default = "default_av_timeout_action")]
    pub on_scanner_timeout: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub name: String,
    pub command: String,
    #[serde(default = "default_clean_codes")]
    pub clean_exit_codes: Vec<i32>,
    #[serde(default = "default_virus_codes")]
    pub virus_exit_codes: Vec<i32>,
    #[serde(default = "default_error_codes")]
    pub error_exit_codes: Vec<i32>,
    #[serde(default = "default_scanner_timeout")]
    pub timeout: String,
    #[serde(default)]
    pub virus_name_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainOverride {
    pub domain: String,
    #[serde(default)]
    pub possible_spam_threshold: Option<u8>,
    #[serde(default)]
    pub definite_spam_threshold: Option<u8>,
    #[serde(default)]
    pub disabled_checks: Vec<String>,
}

// =============================================================================
// Relay
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Vec<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default = "default_spool_dir")]
    pub spool_dir: PathBuf,
    #[serde(default = "default_max_queue")]
    pub max_queue_size: usize,
    #[serde(default = "default_delivery_threads")]
    pub delivery_threads: usize,

    #[serde(default)]
    pub trusted_hosts: TrustedHostsConfig,
    #[serde(default)]
    pub retry: RetryConfig,
    #[serde(default)]
    pub tls: RelayTlsConfig,
    #[serde(default)]
    pub dkim: RelayDkimConfig,
    #[serde(default)]
    pub dmarc_publish: RelayDmarcPublishConfig,
    #[serde(default)]
    pub spf_publish: RelaySpfPublishConfig,
    #[serde(default)]
    pub outbound_policy: OutboundPolicyConfig,
    #[serde(default)]
    pub bounce: BounceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustedHostsConfig {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub require_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_retry_intervals")]
    pub intervals: Vec<String>,
    #[serde(default = "default_max_age")]
    pub max_age: String,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayTlsConfig {
    #[serde(default = "default_true")]
    pub opportunistic: bool,
    #[serde(default)]
    pub verify_certificates: bool,
    #[serde(default = "default_tls_min_version")]
    pub min_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayDkimConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<DkimDomainConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimDomainConfig {
    pub domain: String,
    pub selector: String,
    pub key_file: PathBuf,
    #[serde(default = "default_dkim_algorithm")]
    pub algorithm: String,
}

// ---------------------------------------------------------------------------
// DMARC publish (DNS record management for owned domains)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayDmarcPublishConfig {
    #[serde(default)]
    pub domains: Vec<DmarcPolicyDomain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcPolicyDomain {
    pub domain: String,
    #[serde(default = "default_dmarc_publish_policy")]
    pub policy: String, // "none" | "quarantine" | "reject"
    #[serde(default)]
    pub subdomain_policy: Option<String>,
    #[serde(default = "default_hundred")]
    pub pct: u8,
    #[serde(default)]
    pub rua: Vec<String>,
    #[serde(default)]
    pub ruf: Vec<String>,
    #[serde(default = "default_relaxed_alignment")]
    pub adkim: String, // "r" (relaxed) | "s" (strict)
    #[serde(default = "default_relaxed_alignment")]
    pub aspf: String,
}

// ---------------------------------------------------------------------------
// SPF publish (DNS record management for owned domains)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelaySpfPublishConfig {
    #[serde(default)]
    pub domains: Vec<SpfDomainConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfDomainConfig {
    pub domain: String,
    #[serde(default)]
    pub mechanisms: Vec<SpfMechanism>,
    #[serde(default = "default_spf_all")]
    pub all: String, // "-all" | "~all" | "+all" | "?all"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfMechanism {
    #[serde(default = "default_spf_qualifier")]
    pub qualifier: String, // "+" | "-" | "~" | "?"
    pub mechanism: String, // "include", "ip4", "ip6", "a", "mx", "ptr", "exists"
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutboundPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    #[serde(default = "default_max_recipients")]
    pub max_recipients_per_message: usize,
    #[serde(default)]
    pub allowed_sender_domains: Vec<String>,
    #[serde(default = "default_domain_rate")]
    pub max_messages_per_domain_per_hour: u64,
    #[serde(default = "default_true")]
    pub block_dangerous_attachments: bool,
    #[serde(default)]
    pub check_urls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BounceConfig {
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default = "default_true")]
    pub include_original_headers: bool,
}

// =============================================================================
// Enums
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolType {
    Https,
    Smtps,
    SmtpStarttls,
    Imaps,
    Tcp,
    Stratum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BalanceMethod {
    RoundRobin,
    LeastConnections,
    IpHash,
    /// Sticky sessions: uses a cookie to route repeat clients to the same backend.
    StickySession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    ApacheCombined,
    ApacheCustom,
    Postfix,
    Protocol,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AclDefaultAction {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Blocking,
    DetectionOnly,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckType {
    Tcp,
    Http,
    Smtp,
    Imap,
    Stratum,
}

// =============================================================================
// Default value functions
// =============================================================================

fn default_daemon_name() -> String { "serverwall".into() }
fn default_max_connections() -> usize { 65536 }
fn default_log_dir() -> PathBuf { PathBuf::from("/opt/serverwall/var/log") }
fn default_cert_dir() -> PathBuf { PathBuf::from("/opt/serverwall/etc/certs") }
fn default_log_level() -> String { "info".into() }
fn default_drain_timeout() -> u64 { 30 }
fn default_webui_listen() -> String { "0.0.0.0:8443".into() }
fn default_webui_allow_list() -> Vec<String> { vec!["0.0.0.0/0".to_string(), "::/0".to_string()] }
fn default_webui_cert() -> Option<PathBuf> { Some(PathBuf::from("/opt/serverwall/etc/certs/webui.pem")) }
fn default_webui_key() -> Option<PathBuf> { Some(PathBuf::from("/opt/serverwall/etc/certs/webui-key.pem")) }
fn default_tokens_file() -> PathBuf { PathBuf::from("/opt/serverwall/etc/api-tokens.toml") }
fn default_web_users_file() -> PathBuf { PathBuf::from("/opt/serverwall/etc/web-users.toml") }
fn default_acme_directory() -> String { "https://acme-v02.api.letsencrypt.org/directory".into() }
fn default_acme_challenge() -> String { "http-01".into() }
fn default_acme_storage() -> PathBuf { PathBuf::from("/opt/serverwall/etc/acme") }
fn default_acme_allowed_cidrs() -> Vec<String> {
    vec![
        "64.112.15.0/24".into(),  // ISRG / Let's Encrypt primary
        "66.133.109.0/24".into(), // ISRG / Let's Encrypt secondary
    ]
}
fn default_renew_days() -> u32 { 30 }
fn default_compress_min_size() -> usize { 1024 }
fn default_compress_types() -> Vec<String> {
    vec![
        "text/html".into(), "text/css".into(), "text/javascript".into(),
        "text/plain".into(), "text/xml".into(),
        "application/javascript".into(), "application/json".into(),
        "application/xml".into(), "image/svg+xml".into(),
    ]
}
fn default_tls_min_version() -> String { "1.2".into() }
fn default_balance_method() -> BalanceMethod { BalanceMethod::RoundRobin }
fn default_session_cookie() -> String { "_s".into() }
fn default_log_format() -> LogFormat { LogFormat::ApacheCombined }
fn default_acl_action() -> AclDefaultAction { AclDefaultAction::Allow }
fn default_true() -> bool { true }
fn default_profile_type() -> String { "HTTP".to_string() }
fn default_weight() -> u32 { 1 }
fn default_health_interval() -> String { "10s".into() }
fn default_health_timeout() -> String { "3s".into() }
fn default_health_type() -> HealthCheckType { HealthCheckType::Tcp }
fn default_health_expect() -> u16 { 200 }
fn default_health_method() -> String { "GET".into() }
fn default_waf_mode() -> WafMode { WafMode::Blocking }
fn default_anomaly_threshold() -> u32 { 5 }
fn default_paranoia_level() -> u8 { 1 }
fn default_one() -> u8 { 1 }
fn default_waf_rule_action() -> String { "block".into() }
fn default_rate_key() -> String { "client_ip".into() }
fn default_cookie_size() -> usize { 4096 }
fn default_possible_spam() -> u8 { 40 }
fn default_definite_spam() -> u8 { 80 }
fn default_check_duration() -> String { "10s".into() }
fn default_check_weight() -> f64 { 3.0 }
fn default_dnsbl_weight() -> f64 { 8.0 }
fn default_dnsbl_timeout() -> String { "5s".into() }
fn default_geoip_db_path() -> Option<PathBuf> {
    Some(PathBuf::from("/opt/serverwall/lib/geoip/dbip-country-lite.mmdb"))
}
fn default_residential_weight() -> f64 { 10.0 }
fn default_pbl_zone() -> String { "pbl.spamhaus.org".into() }
fn default_one_f64() -> f64 { 1.0 }
fn default_half_f64() -> f64 { 0.5 }
fn default_point_one() -> f64 { 0.1 }
fn default_point_three() -> f64 { 0.3 }
fn default_spf_weight() -> f64 { 6.0 }
fn default_rate_weight() -> f64 { 5.0 }
fn default_rate_max() -> u64 { 100 }
fn default_rate_window() -> String { "1h".into() }
fn default_dmarc_weight() -> f64 { 7.0 }
fn default_content_weight() -> f64 { 5.0 }
fn default_url_weight() -> f64 { 5.0 }
fn default_attachment_weight() -> f64 { 6.0 }
fn default_av_weight() -> f64 { 10.0 }
fn default_av_error_action() -> String { "pass".into() }
fn default_av_timeout_action() -> String { "tempfail".into() }
fn default_clean_codes() -> Vec<i32> { vec![0] }
fn default_virus_codes() -> Vec<i32> { vec![1] }
fn default_error_codes() -> Vec<i32> { vec![2] }
fn default_scanner_timeout() -> String { "30s".into() }
fn default_spool_dir() -> PathBuf { PathBuf::from("/opt/serverwall/var/spool") }
fn default_max_queue() -> usize { 10000 }
fn default_delivery_threads() -> usize { 4 }
fn default_max_message_size() -> usize { 26_214_400 }
fn default_max_recipients() -> usize { 100 }
fn default_domain_rate() -> u64 { 500 }
fn default_dkim_algorithm() -> String { "rsa-sha256".into() }
fn default_dmarc_publish_policy() -> String { "none".into() }
fn default_relaxed_alignment() -> String { "r".into() }
fn default_hundred() -> u8 { 100 }
fn default_spf_all() -> String { "-all".into() }
fn default_spf_qualifier() -> String { "+".into() }
fn default_max_age() -> String { "5d".into() }
fn default_max_attempts() -> u32 { 25 }

fn default_retry_intervals() -> Vec<String> {
    vec!["5m", "10m", "30m", "1h", "2h", "4h", "8h", "12h"]
        .into_iter().map(String::from).collect()
}

fn default_dangerous_extensions() -> Vec<String> {
    vec!["exe", "scr", "bat", "cmd", "ps1", "vbs", "js", "msi", "dll", "hta"]
        .into_iter().map(String::from).collect()
}

// =============================================================================
// Default impls
// =============================================================================

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            daemon_name: default_daemon_name(),
            pid_file: None,
            worker_threads: 0,
            max_connections: default_max_connections(),
            log_dir: default_log_dir(),
            cert_dir: default_cert_dir(),
            config_dir: None,
            log_level: default_log_level(),
            graceful_drain_secs: default_drain_timeout(),
        }
    }
}

impl Default for WebuiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_webui_listen(),
            tls_cert: default_webui_cert(),
            tls_key: default_webui_key(),
            tokens_file: default_tokens_file(),
            web_users_file: default_web_users_file(),
            allowed_origins: Vec::new(),
            allow_list: default_webui_allow_list(),
        }
    }
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            email: None,
            directory_url: default_acme_directory(),
            challenge_type: default_acme_challenge(),
            storage_dir: default_acme_storage(),
            auto_renew: true,
            renew_before_days: default_renew_days(),
            challenge_allowed_cidrs: default_acme_allowed_cidrs(),
        }
    }
}

impl Default for ServerWallConfig {
    fn default() -> Self {
        Self {
            global: GlobalConfig::default(),
            webui: WebuiConfig::default(),
            acme: AcmeConfig::default(),
            frontend: Vec::new(),
            backend_pool: Vec::new(),
            waf_ruleset: Vec::new(),
            security_profiles: Vec::new(),
            log_profiles: Vec::new(),
            security: SecurityConfig::default(),
            antispam: AntispamConfig::default(),
            relay: RelayConfig::default(),
        }
    }
}

impl Default for SpfSeverityConfig {
    fn default() -> Self {
        Self {
            fail: 1.0,
            softfail: 0.5,
            neutral: 0.1,
            none: 0.3,
        }
    }
}

impl Default for SmtpRateRule {
    fn default() -> Self {
        Self {
            max: default_rate_max(),
            window: default_rate_window(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            intervals: default_retry_intervals(),
            max_age: default_max_age(),
            max_attempts: default_max_attempts(),
        }
    }
}
