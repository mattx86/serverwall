use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::{editor, load_config};
use serverwall_core::config::editor::{
    AntispamChecksUpdate, AntivirusFieldUpdate, CheckFieldUpdate, ResidentialSpfFieldUpdate,
};
use serverwall_core::config::schema::{DnsblListEntry, DomainOverride, ScannerConfig};

use crate::commands::maybe_reload;
use crate::output;

#[derive(Args)]
pub struct AntispamArgs {
    #[command(subcommand)]
    pub action: AntispamAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum AntispamAction {
    /// Show antispam configuration summary.
    Show,
    /// Update top-level antispam settings.
    Set {
        /// Enable antispam filtering.
        #[arg(long)]
        enabled: Option<bool>,
        /// Score threshold (%) at which a message is considered possible spam.
        #[arg(long)]
        possible_spam: Option<u8>,
        /// Score threshold (%) at which a message is considered definite spam.
        #[arg(long)]
        definite_spam: Option<u8>,
        /// Maximum duration to run all checks (e.g. 30s).
        #[arg(long)]
        max_duration: Option<String>,
    },
    /// Update check enabled/weight settings (only specified checks are changed).
    SetChecks {
        /// Load a complete AntispamChecksUpdate from a JSON file (conflicts with all per-check flags).
        #[arg(long, conflicts_with_all = [
            "dnsbl_enabled","dnsbl_weight","spf_enabled","spf_weight","dkim_enabled","dkim_weight",
            "dmarc_enabled","dmarc_weight","rdns_enabled","rdns_weight","helo_enabled","helo_weight",
            "early_talker_enabled","early_talker_weight","content_enabled","content_weight",
            "url_analysis_enabled","url_analysis_weight","attachment_enabled","attachment_weight",
            "html_enabled","html_weight","header_analysis_enabled","header_analysis_weight",
            "charset_enabled","charset_weight","bulk_enabled","bulk_weight","ratio_enabled","ratio_weight",
            "antivirus_enabled","antivirus_weight","antivirus_reject_on_virus",
            "residential_spf_enabled","residential_spf_weight","residential_spf_reject",
            "residential_spf_check_pbl","residential_spf_pbl_zone","residential_spf_softfail_triggers",
            "residential_spf_neutral_triggers","spf_fail_weight","spf_softfail_weight",
            "spf_neutral_weight","spf_none_weight",
        ])]
        from_json: Option<String>,
        #[arg(long)] dnsbl_enabled: Option<bool>,
        #[arg(long)] dnsbl_weight: Option<f64>,
        #[arg(long)] spf_enabled: Option<bool>,
        #[arg(long)] spf_weight: Option<f64>,
        #[arg(long)] dkim_enabled: Option<bool>,
        #[arg(long)] dkim_weight: Option<f64>,
        #[arg(long)] dmarc_enabled: Option<bool>,
        #[arg(long)] dmarc_weight: Option<f64>,
        #[arg(long)] rdns_enabled: Option<bool>,
        #[arg(long)] rdns_weight: Option<f64>,
        #[arg(long)] helo_enabled: Option<bool>,
        #[arg(long)] helo_weight: Option<f64>,
        #[arg(long)] early_talker_enabled: Option<bool>,
        #[arg(long)] early_talker_weight: Option<f64>,
        #[arg(long)] content_enabled: Option<bool>,
        #[arg(long)] content_weight: Option<f64>,
        #[arg(long)] url_analysis_enabled: Option<bool>,
        #[arg(long)] url_analysis_weight: Option<f64>,
        #[arg(long)] attachment_enabled: Option<bool>,
        #[arg(long)] attachment_weight: Option<f64>,
        #[arg(long)] html_enabled: Option<bool>,
        #[arg(long)] html_weight: Option<f64>,
        #[arg(long)] header_analysis_enabled: Option<bool>,
        #[arg(long)] header_analysis_weight: Option<f64>,
        #[arg(long)] charset_enabled: Option<bool>,
        #[arg(long)] charset_weight: Option<f64>,
        #[arg(long)] bulk_enabled: Option<bool>,
        #[arg(long)] bulk_weight: Option<f64>,
        #[arg(long)] ratio_enabled: Option<bool>,
        #[arg(long)] ratio_weight: Option<f64>,
        #[arg(long)] antivirus_enabled: Option<bool>,
        #[arg(long)] antivirus_weight: Option<f64>,
        #[arg(long)] antivirus_reject_on_virus: Option<bool>,
        #[arg(long)] residential_spf_enabled: Option<bool>,
        #[arg(long)] residential_spf_weight: Option<f64>,
        #[arg(long)] residential_spf_reject: Option<bool>,
        #[arg(long)] residential_spf_check_pbl: Option<bool>,
        #[arg(long)] residential_spf_pbl_zone: Option<String>,
        #[arg(long)] residential_spf_softfail_triggers: Option<bool>,
        /// Treat SPF neutral result as a trigger for residential SPF scoring.
        #[arg(long)] residential_spf_neutral_triggers: Option<bool>,
        /// Weight multiplier for SPF fail result (0.0–1.0).
        #[arg(long)] spf_fail_weight: Option<f64>,
        /// Weight multiplier for SPF softfail result (0.0–1.0).
        #[arg(long)] spf_softfail_weight: Option<f64>,
        /// Weight multiplier for SPF neutral result (0.0–1.0).
        #[arg(long)] spf_neutral_weight: Option<f64>,
        /// Weight multiplier for SPF none result (0.0–1.0).
        #[arg(long)] spf_none_weight: Option<f64>,
    },
    // ---- Allow list ----
    /// Add an IP to the antispam allow list.
    AddAllowIp { ip: String },
    /// Remove an IP from the antispam allow list.
    RemoveAllowIp { ip: String },
    /// Add a sender address to the antispam allow list.
    AddAllowSender { sender: String },
    /// Remove a sender address from the antispam allow list.
    RemoveAllowSender { sender: String },
    /// Add a sender domain to the antispam allow list.
    AddAllowDomain { domain: String },
    /// Remove a sender domain from the antispam allow list.
    RemoveAllowDomain { domain: String },
    /// Add a recipient address to the antispam allow list.
    AddAllowRecipient { recipient: String },
    /// Remove a recipient address from the antispam allow list.
    RemoveAllowRecipient { recipient: String },
    // ---- Block list ----
    /// Add an IP to the antispam block list.
    AddBlockIp { ip: String },
    /// Remove an IP from the antispam block list.
    RemoveBlockIp { ip: String },
    /// Add a sender address to the antispam block list.
    AddBlockSender { sender: String },
    /// Remove a sender address from the antispam block list.
    RemoveBlockSender { sender: String },
    /// Add a sender domain to the antispam block list.
    AddBlockDomain { domain: String },
    /// Remove a sender domain from the antispam block list.
    RemoveBlockDomain { domain: String },
    /// Add a recipient address to the antispam block list.
    AddBlockRecipient { recipient: String },
    /// Remove a recipient address from the antispam block list.
    RemoveBlockRecipient { recipient: String },
    // ---- DNSBL ----
    /// Add a DNSBL zone.
    AddDnsbl {
        /// DNSBL zone hostname (e.g. zen.spamhaus.org).
        zone: String,
        /// Weight multiplier applied when this zone gets a hit.
        #[arg(long, default_value = "1.0")]
        weight_multiplier: f64,
        /// Reject message immediately on hit (no scoring).
        #[arg(long)]
        reject_on_hit: bool,
    },
    /// Remove a DNSBL zone by hostname.
    RemoveDnsbl { zone: String },
    // ---- SURBL ----
    /// Add a SURBL/URIBL zone.
    AddSurbl { zone: String },
    /// Remove a SURBL/URIBL zone.
    RemoveSurbl { zone: String },
    // ---- Antivirus scanners ----
    /// Add an external antivirus scanner.
    AddScanner {
        /// Scanner name (unique identifier).
        name: String,
        /// Command to run (use %f as placeholder for the message temp file path).
        #[arg(long)]
        command: String,
        /// Scanner timeout (e.g. 30s).
        #[arg(long, default_value = "30s")]
        timeout: String,
        /// Exit codes that indicate a clean message (comma-separated).
        #[arg(long, value_delimiter = ',', default_value = "0")]
        clean_exit_codes: Vec<i32>,
        /// Exit codes that indicate a virus was found (comma-separated).
        #[arg(long, value_delimiter = ',', default_value = "1")]
        virus_exit_codes: Vec<i32>,
        /// Exit codes that indicate a scanner error (comma-separated).
        #[arg(long, value_delimiter = ',', default_value = "2")]
        error_exit_codes: Vec<i32>,
        /// Regex pattern to extract virus name from scanner output.
        #[arg(long)]
        virus_name_pattern: Option<String>,
    },
    /// Remove an antivirus scanner by name.
    RemoveScanner { name: String },
    /// List configured antivirus scanners.
    ListScanners,
    // ---- Domain overrides ----
    /// Add a per-domain antispam threshold override.
    AddDomainOverride {
        /// Domain name (e.g. example.com).
        domain: String,
        /// Override possible-spam threshold for this domain.
        #[arg(long)]
        possible_spam: Option<u8>,
        /// Override definite-spam threshold for this domain.
        #[arg(long)]
        definite_spam: Option<u8>,
        /// Comma-separated list of checks to disable for this domain.
        #[arg(long, value_delimiter = ',')]
        disable_checks: Vec<String>,
    },
    /// Update a per-domain antispam threshold override.
    UpdateDomainOverride {
        /// Domain name.
        domain: String,
        /// Override possible-spam threshold.
        #[arg(long)]
        possible_spam: Option<u8>,
        /// Override definite-spam threshold.
        #[arg(long)]
        definite_spam: Option<u8>,
        /// Comma-separated list of checks to disable (replaces existing list).
        #[arg(long, value_delimiter = ',')]
        disable_checks: Option<Vec<String>>,
    },
    /// Remove a per-domain antispam threshold override.
    RemoveDomainOverride { domain: String },
    /// List per-domain antispam overrides.
    ListDomainOverrides,
    // ---- Lists ----
    /// List antispam allow/block list entries.
    ListEntries,
}

pub fn run(config_path: &Path, args: AntispamArgs, no_reload: bool) -> anyhow::Result<()> {
    match args.action {
        AntispamAction::Show => {
            let config = load_config(config_path)?;
            let a = &config.antispam;

            if args.json {
                let json = serde_json::json!({
                    "enabled": a.enabled,
                    "possible_spam_threshold": a.possible_spam_threshold,
                    "definite_spam_threshold": a.definite_spam_threshold,
                    "max_check_duration": a.max_check_duration,
                    "checks": {
                        "dnsbl": { "enabled": a.dnsbl.enabled, "weight": a.dnsbl.weight },
                        "spf": { "enabled": a.spf.enabled, "weight": a.spf.weight },
                        "dkim": { "enabled": a.dkim.enabled, "weight": a.dkim.weight },
                        "dmarc": { "enabled": a.dmarc.enabled, "weight": a.dmarc.weight },
                        "rdns": { "enabled": a.rdns.enabled, "weight": a.rdns.weight },
                        "helo": { "enabled": a.helo.enabled, "weight": a.helo.weight },
                        "early_talker": { "enabled": a.early_talker.enabled, "weight": a.early_talker.weight },
                        "content": { "enabled": a.content.enabled, "weight": a.content.weight },
                        "url_analysis": { "enabled": a.url_analysis.enabled, "weight": a.url_analysis.weight },
                        "attachment": { "enabled": a.attachment.enabled, "weight": a.attachment.weight },
                        "html": { "enabled": a.html.enabled, "weight": a.html.weight },
                        "header_analysis": { "enabled": a.header_analysis.enabled, "weight": a.header_analysis.weight },
                        "charset": { "enabled": a.charset.enabled, "weight": a.charset.weight },
                        "bulk": { "enabled": a.bulk.enabled, "weight": a.bulk.weight },
                        "ratio": { "enabled": a.ratio.enabled, "weight": a.ratio.weight },
                        "antivirus": { "enabled": a.antivirus.enabled, "weight": a.antivirus.weight },
                        "residential_spf": {
                            "enabled": a.residential_spf.enabled,
                            "weight": a.residential_spf.weight,
                            "neutral_triggers": a.residential_spf.neutral_triggers,
                        },
                    }
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
                return Ok(());
            }

            println!("Antispam Configuration");
            println!("======================");
            println!("Enabled:         {}", a.enabled);
            println!("Possible Spam:   {}%", a.possible_spam_threshold);
            println!("Definite Spam:   {}%", a.definite_spam_threshold);
            println!("Max Duration:    {}", a.max_check_duration);
            println!();
            println!("Checks:");
            let rows = vec![
                vec!["dnsbl".into(),            yn(a.dnsbl.enabled),            a.dnsbl.weight.to_string()],
                vec!["spf".into(),              yn(a.spf.enabled),              a.spf.weight.to_string()],
                vec!["dkim".into(),             yn(a.dkim.enabled),             a.dkim.weight.to_string()],
                vec!["dmarc".into(),            yn(a.dmarc.enabled),            a.dmarc.weight.to_string()],
                vec!["rdns".into(),             yn(a.rdns.enabled),             a.rdns.weight.to_string()],
                vec!["helo".into(),             yn(a.helo.enabled),             a.helo.weight.to_string()],
                vec!["early_talker".into(),     yn(a.early_talker.enabled),     a.early_talker.weight.to_string()],
                vec!["content".into(),          yn(a.content.enabled),          a.content.weight.to_string()],
                vec!["url_analysis".into(),     yn(a.url_analysis.enabled),     a.url_analysis.weight.to_string()],
                vec!["attachment".into(),       yn(a.attachment.enabled),       a.attachment.weight.to_string()],
                vec!["html".into(),             yn(a.html.enabled),             a.html.weight.to_string()],
                vec!["header_analysis".into(),  yn(a.header_analysis.enabled),  a.header_analysis.weight.to_string()],
                vec!["charset".into(),          yn(a.charset.enabled),          a.charset.weight.to_string()],
                vec!["bulk".into(),             yn(a.bulk.enabled),             a.bulk.weight.to_string()],
                vec!["ratio".into(),            yn(a.ratio.enabled),            a.ratio.weight.to_string()],
                vec!["antivirus".into(),        yn(a.antivirus.enabled),        a.antivirus.weight.to_string()],
                vec!["residential_spf".into(),  yn(a.residential_spf.enabled),  a.residential_spf.weight.to_string()],
            ];
            output::print_table(&["CHECK", "ENABLED", "WEIGHT"], &rows);
        }

        AntispamAction::Set { enabled, possible_spam, definite_spam, max_duration } => {
            let mut update = AntispamChecksUpdate::default();
            update.enabled = enabled;
            update.possible_spam_threshold = possible_spam;
            update.definite_spam_threshold = definite_spam;
            update.max_check_duration = max_duration;
            editor::update_antispam_checks(config_path, update)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Antispam settings updated.");
            maybe_reload(no_reload);
        }

        AntispamAction::SetChecks {
            from_json,
            dnsbl_enabled, dnsbl_weight,
            spf_enabled, spf_weight,
            dkim_enabled, dkim_weight,
            dmarc_enabled, dmarc_weight,
            rdns_enabled, rdns_weight,
            helo_enabled, helo_weight,
            early_talker_enabled, early_talker_weight,
            content_enabled, content_weight,
            url_analysis_enabled, url_analysis_weight,
            attachment_enabled, attachment_weight,
            html_enabled, html_weight,
            header_analysis_enabled, header_analysis_weight,
            charset_enabled, charset_weight,
            bulk_enabled, bulk_weight,
            ratio_enabled, ratio_weight,
            antivirus_enabled, antivirus_weight, antivirus_reject_on_virus,
            residential_spf_enabled, residential_spf_weight, residential_spf_reject,
            residential_spf_check_pbl, residential_spf_pbl_zone,
            residential_spf_softfail_triggers, residential_spf_neutral_triggers,
            spf_fail_weight, spf_softfail_weight, spf_neutral_weight, spf_none_weight,
        } => {
            if let Some(ref path) = from_json {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("failed to read '{}': {}", path, e))?;
                let update: AntispamChecksUpdate = serde_json::from_str(&content)
                    .map_err(|e| anyhow::anyhow!("invalid JSON: {}", e))?;
                editor::update_antispam_checks(config_path, update)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                println!("Antispam check settings updated from file.");
                maybe_reload(no_reload);
                return Ok(());
            }
            // Apply SPF severity updates via full config read+write
            let needs_spf_severity = spf_fail_weight.is_some() || spf_softfail_weight.is_some()
                || spf_neutral_weight.is_some() || spf_none_weight.is_some();

            if needs_spf_severity {
                let config = load_config(config_path)?;
                let mut a = config.antispam.clone();
                if let Some(v) = spf_fail_weight    { a.spf.severity.fail    = v; }
                if let Some(v) = spf_softfail_weight{ a.spf.severity.softfail = v; }
                if let Some(v) = spf_neutral_weight { a.spf.severity.neutral  = v; }
                if let Some(v) = spf_none_weight    { a.spf.severity.none     = v; }
                editor::set_antispam_config(config_path, a)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
            }

            let mk = |enabled: Option<bool>, weight: Option<f64>| -> Option<CheckFieldUpdate> {
                if enabled.is_some() || weight.is_some() {
                    Some(CheckFieldUpdate { enabled, weight })
                } else {
                    None
                }
            };
            let av = if antivirus_enabled.is_some() || antivirus_weight.is_some() || antivirus_reject_on_virus.is_some() {
                Some(AntivirusFieldUpdate {
                    enabled: antivirus_enabled, weight: antivirus_weight,
                    reject_on_virus: antivirus_reject_on_virus,
                    on_scanner_error: None, on_scanner_timeout: None,
                })
            } else { None };
            let rspf = if residential_spf_enabled.is_some() || residential_spf_weight.is_some()
                || residential_spf_reject.is_some() || residential_spf_check_pbl.is_some()
                || residential_spf_pbl_zone.is_some() || residential_spf_softfail_triggers.is_some()
                || residential_spf_neutral_triggers.is_some()
            {
                Some(ResidentialSpfFieldUpdate {
                    enabled: residential_spf_enabled,
                    weight: residential_spf_weight,
                    reject: residential_spf_reject,
                    check_pbl: residential_spf_check_pbl,
                    pbl_zone: residential_spf_pbl_zone,
                    softfail_triggers: residential_spf_softfail_triggers,
                    neutral_triggers: residential_spf_neutral_triggers,
                })
            } else { None };

            let update = AntispamChecksUpdate {
                dnsbl:          mk(dnsbl_enabled, dnsbl_weight),
                spf:            mk(spf_enabled, spf_weight),
                dkim:           mk(dkim_enabled, dkim_weight),
                dmarc:          mk(dmarc_enabled, dmarc_weight),
                rdns:           mk(rdns_enabled, rdns_weight),
                helo:           mk(helo_enabled, helo_weight),
                early_talker:   mk(early_talker_enabled, early_talker_weight),
                content:        mk(content_enabled, content_weight),
                url_analysis:   mk(url_analysis_enabled, url_analysis_weight),
                attachment:     mk(attachment_enabled, attachment_weight),
                html:           mk(html_enabled, html_weight),
                header_analysis:mk(header_analysis_enabled, header_analysis_weight),
                charset:        mk(charset_enabled, charset_weight),
                bulk:           mk(bulk_enabled, bulk_weight),
                ratio:          mk(ratio_enabled, ratio_weight),
                antivirus: av,
                residential_spf: rspf,
                ..AntispamChecksUpdate::default()
            };
            editor::update_antispam_checks(config_path, update)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Antispam check settings updated.");
            maybe_reload(no_reload);
        }

        // Allow list
        AntispamAction::AddAllowIp { ip } => {
            editor::add_antispam_allow_ip(config_path, &ip).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("IP '{}' added to allow list.", ip); maybe_reload(no_reload);
        }
        AntispamAction::RemoveAllowIp { ip } => {
            editor::remove_antispam_allow_ip(config_path, &ip).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("IP '{}' removed from allow list.", ip); maybe_reload(no_reload);
        }
        AntispamAction::AddAllowSender { sender } => {
            editor::add_antispam_allow_sender(config_path, &sender).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Sender '{}' added to allow list.", sender); maybe_reload(no_reload);
        }
        AntispamAction::RemoveAllowSender { sender } => {
            editor::remove_antispam_allow_sender(config_path, &sender).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Sender '{}' removed from allow list.", sender); maybe_reload(no_reload);
        }
        AntispamAction::AddAllowDomain { domain } => {
            editor::add_antispam_allow_domain(config_path, &domain).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Domain '{}' added to allow list.", domain); maybe_reload(no_reload);
        }
        AntispamAction::RemoveAllowDomain { domain } => {
            editor::remove_antispam_allow_domain(config_path, &domain).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Domain '{}' removed from allow list.", domain); maybe_reload(no_reload);
        }
        AntispamAction::AddAllowRecipient { recipient } => {
            editor::add_antispam_allow_recipient(config_path, &recipient).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Recipient '{}' added to allow list.", recipient); maybe_reload(no_reload);
        }
        AntispamAction::RemoveAllowRecipient { recipient } => {
            editor::remove_antispam_allow_recipient(config_path, &recipient).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Recipient '{}' removed from allow list.", recipient); maybe_reload(no_reload);
        }

        // Block list
        AntispamAction::AddBlockIp { ip } => {
            editor::add_antispam_block_ip(config_path, &ip).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("IP '{}' added to block list.", ip); maybe_reload(no_reload);
        }
        AntispamAction::RemoveBlockIp { ip } => {
            editor::remove_antispam_block_ip(config_path, &ip).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("IP '{}' removed from block list.", ip); maybe_reload(no_reload);
        }
        AntispamAction::AddBlockSender { sender } => {
            editor::add_antispam_block_sender(config_path, &sender).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Sender '{}' added to block list.", sender); maybe_reload(no_reload);
        }
        AntispamAction::RemoveBlockSender { sender } => {
            editor::remove_antispam_block_sender(config_path, &sender).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Sender '{}' removed from block list.", sender); maybe_reload(no_reload);
        }
        AntispamAction::AddBlockDomain { domain } => {
            editor::add_antispam_block_domain(config_path, &domain).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Domain '{}' added to block list.", domain); maybe_reload(no_reload);
        }
        AntispamAction::RemoveBlockDomain { domain } => {
            editor::remove_antispam_block_domain(config_path, &domain).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Domain '{}' removed from block list.", domain); maybe_reload(no_reload);
        }
        AntispamAction::AddBlockRecipient { recipient } => {
            editor::add_antispam_block_recipient(config_path, &recipient).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Recipient '{}' added to block list.", recipient); maybe_reload(no_reload);
        }
        AntispamAction::RemoveBlockRecipient { recipient } => {
            editor::remove_antispam_block_recipient(config_path, &recipient).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Recipient '{}' removed from block list.", recipient); maybe_reload(no_reload);
        }

        // DNSBL
        AntispamAction::AddDnsbl { zone, weight_multiplier, reject_on_hit } => {
            let entry = DnsblListEntry { zone: zone.clone(), weight_multiplier, reject_on_hit };
            editor::add_antispam_dnsbl_zone(config_path, entry).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("DNSBL zone '{}' added.", zone); maybe_reload(no_reload);
        }
        AntispamAction::RemoveDnsbl { zone } => {
            editor::remove_antispam_dnsbl_zone(config_path, &zone).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("DNSBL zone '{}' removed.", zone); maybe_reload(no_reload);
        }

        // SURBL
        AntispamAction::AddSurbl { zone } => {
            editor::add_antispam_surbl_zone(config_path, zone.clone()).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("SURBL zone '{}' added.", zone); maybe_reload(no_reload);
        }
        AntispamAction::RemoveSurbl { zone } => {
            editor::remove_antispam_surbl_zone(config_path, &zone).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("SURBL zone '{}' removed.", zone); maybe_reload(no_reload);
        }

        // Scanners
        AntispamAction::AddScanner { name, command, timeout, clean_exit_codes, virus_exit_codes, error_exit_codes, virus_name_pattern } => {
            let scanner = ScannerConfig {
                name: name.clone(), command, timeout,
                clean_exit_codes, virus_exit_codes, error_exit_codes,
                virus_name_pattern,
            };
            editor::add_antispam_scanner(config_path, scanner).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Scanner '{}' added.", name); maybe_reload(no_reload);
        }
        AntispamAction::RemoveScanner { name } => {
            editor::remove_antispam_scanner(config_path, &name).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Scanner '{}' removed.", name); maybe_reload(no_reload);
        }
        AntispamAction::ListScanners => {
            let config = load_config(config_path)?;
            if config.antispam.antivirus.scanners.is_empty() {
                println!("No antivirus scanners configured.");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = config.antispam.antivirus.scanners.iter().map(|s| vec![
                s.name.clone(), s.command.clone(), s.timeout.clone(),
            ]).collect();
            output::print_table(&["NAME", "COMMAND", "TIMEOUT"], &rows);
        }

        // Domain overrides
        AntispamAction::AddDomainOverride { domain, possible_spam, definite_spam, disable_checks } => {
            let entry = DomainOverride { domain: domain.clone(), possible_spam_threshold: possible_spam,
                definite_spam_threshold: definite_spam, disabled_checks: disable_checks };
            editor::add_antispam_domain_override(config_path, entry).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Domain override for '{}' added.", domain); maybe_reload(no_reload);
        }
        AntispamAction::UpdateDomainOverride { domain, possible_spam, definite_spam, disable_checks } => {
            let config = load_config(config_path)?;
            let mut entry = config.antispam.domain_overrides.iter().find(|d| d.domain == domain)
                .ok_or_else(|| anyhow::anyhow!("domain override for '{}' not found", domain))?.clone();
            if let Some(v) = possible_spam { entry.possible_spam_threshold = Some(v); }
            if let Some(v) = definite_spam { entry.definite_spam_threshold = Some(v); }
            if let Some(v) = disable_checks { entry.disabled_checks = v; }
            editor::update_antispam_domain_override(config_path, &domain, entry).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Domain override for '{}' updated.", domain); maybe_reload(no_reload);
        }
        AntispamAction::RemoveDomainOverride { domain } => {
            editor::remove_antispam_domain_override(config_path, &domain).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Domain override for '{}' removed.", domain); maybe_reload(no_reload);
        }
        AntispamAction::ListDomainOverrides => {
            let config = load_config(config_path)?;
            if config.antispam.domain_overrides.is_empty() {
                println!("No domain overrides configured.");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = config.antispam.domain_overrides.iter().map(|d| vec![
                d.domain.clone(),
                d.possible_spam_threshold.map(|v| v.to_string()).unwrap_or_else(|| "(global)".into()),
                d.definite_spam_threshold.map(|v| v.to_string()).unwrap_or_else(|| "(global)".into()),
                d.disabled_checks.join(", "),
            ]).collect();
            output::print_table(&["DOMAIN", "POSSIBLE%", "DEFINITE%", "DISABLED CHECKS"], &rows);
        }

        AntispamAction::ListEntries => {
            let config = load_config(config_path)?;
            let a = &config.antispam;
            let mut rows: Vec<Vec<String>> = Vec::new();
            for ip  in &a.allow.ips           { rows.push(vec!["allow".into(), "ip".into(),     ip.clone()]); }
            for s   in &a.allow.senders       { rows.push(vec!["allow".into(), "sender".into(), s.clone()]); }
            for d   in &a.allow.sender_domains{ rows.push(vec!["allow".into(), "domain".into(), d.clone()]); }
            for r   in &a.allow.recipients    { rows.push(vec!["allow".into(), "recipient".into(),r.clone()]); }
            for ip  in &a.block.ips           { rows.push(vec!["block".into(), "ip".into(),     ip.clone()]); }
            for s   in &a.block.senders       { rows.push(vec!["block".into(), "sender".into(), s.clone()]); }
            for d   in &a.block.sender_domains{ rows.push(vec!["block".into(), "domain".into(), d.clone()]); }
            for r   in &a.block.recipients    { rows.push(vec!["block".into(), "recipient".into(),r.clone()]); }
            if rows.is_empty() {
                println!("No antispam list entries configured.");
            } else {
                output::print_table(&["ACTION", "TYPE", "VALUE"], &rows);
            }
        }
    }
    Ok(())
}

fn yn(v: bool) -> String {
    if v { "yes".into() } else { "no".into() }
}
