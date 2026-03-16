use crate::result::SpamReport;
use crate::score::SpamVerdict;

/// Builds spam-related headers (X-Spam-Score, X-Spam-Status, etc.)
/// to be injected into the message before delivery.
pub struct SpamHeaderBuilder;

impl SpamHeaderBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Build all anti-spam and authentication headers for the report.
    ///
    /// `authserv_id` is the hostname of this server, used in the
    /// Authentication-Results header (RFC 8601).
    pub fn build_headers(
        &self,
        report: &SpamReport,
        authserv_id: &str,
    ) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        // X-Spam-Score: raw numeric score
        headers.push((
            "X-Spam-Score".to_string(),
            format!("{:.1}", report.score.0),
        ));

        // X-Spam-Flag: YES / NO
        let flag = match report.verdict {
            SpamVerdict::Spam => "YES",
            _ => "NO",
        };
        headers.push(("X-Spam-Flag".to_string(), flag.to_string()));

        // X-Spam-Status: Yes/No/Maybe with score summary
        let status_word = match report.verdict {
            SpamVerdict::Clean => "No",
            SpamVerdict::Suspect => "Maybe",
            SpamVerdict::Spam => "Yes",
        };
        let tests: Vec<String> = report
            .contributions
            .iter()
            .map(|c| format!("{}={:.1}", c.check_name, c.score))
            .collect();
        let tests_str = if tests.is_empty() {
            "none".to_string()
        } else {
            tests.join(",")
        };
        headers.push((
            "X-Spam-Status".to_string(),
            format!(
                "{}, score={:.1} tests=[{}]",
                status_word, report.score.0, tests_str,
            ),
        ));

        // X-Spam-Report: human readable list of contributions
        if !report.contributions.is_empty() {
            let lines: Vec<String> = report
                .contributions
                .iter()
                .map(|c| format!("* {:.1} {} -- {}", c.score, c.check_name, c.description))
                .collect();
            headers.push(("X-Spam-Report".to_string(), lines.join("\r\n\t")));
        }

        // Authentication-Results (RFC 8601)
        let auth = &report.auth_results;
        let ar_value = format!(
            "{}; spf={} ; dkim={} ; dmarc={} ; arc={}",
            authserv_id, auth.spf, auth.dkim, auth.dmarc, auth.arc,
        );
        headers.push(("Authentication-Results".to_string(), ar_value));

        headers
    }
}

impl Default for SpamHeaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}
