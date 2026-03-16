use async_trait::async_trait;
use mail_parser::{MessageParser, MimeHeaders};
use regex::Regex;

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Inspects message attachments for suspicious file types, sizes, and content.
pub struct AttachmentCheck {
    pub weight: f64,
    pub dangerous_extensions: Vec<String>,
    double_ext_re: Regex,
}

impl AttachmentCheck {
    pub fn new(weight: f64, dangerous_extensions: Vec<String>) -> Self {
        // Matches double extensions like "invoice.pdf.exe"
        let double_ext_re = Regex::new(
            r"(?i)\.\w{2,4}\.(exe|scr|bat|cmd|ps1|vbs|js|msi|dll|hta|pif|com|cpl|wsf|wsh)$"
        ).unwrap();

        Self {
            weight,
            dangerous_extensions,
            double_ext_re,
        }
    }

    /// Magic bytes check: does the file content match the declared MIME type?
    fn check_magic_bytes(content_type: &str, data: &[u8]) -> bool {
        if data.len() < 4 {
            return true; // Too small to check.
        }
        let mime_lower = content_type.to_lowercase();
        if mime_lower.contains("pdf") {
            return data.starts_with(b"%PDF");
        }
        if mime_lower.contains("zip") || mime_lower.contains("x-zip") {
            return data.starts_with(b"PK");
        }
        if mime_lower.contains("png") {
            return data.starts_with(&[0x89, 0x50, 0x4E, 0x47]);
        }
        if mime_lower.contains("jpeg") || mime_lower.contains("jpg") {
            return data.starts_with(&[0xFF, 0xD8, 0xFF]);
        }
        if mime_lower.contains("gif") {
            return data.starts_with(b"GIF8");
        }
        // Executables declared as something else.
        if !mime_lower.contains("executable")
            && !mime_lower.contains("x-msdos")
            && !mime_lower.contains("x-msdownload")
        {
            if data.starts_with(b"MZ") {
                return false; // PE executable masquerading as other type.
            }
        }
        true
    }
}

#[async_trait]
impl PostDataCheck for AttachmentCheck {
    fn name(&self) -> &str {
        "attachment"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let parsed = match MessageParser::default().parse(&ctx.raw_message) {
            Some(msg) => msg,
            None => {
                return (
                    CheckOutcome::Skip {
                        reason: "Failed to parse MIME".to_string(),
                    },
                    Vec::new(),
                );
            }
        };

        let mut contributions = Vec::new();
        let mut total_severity: f64 = 0.0;

        for attachment in parsed.attachments() {
            let filename = attachment
                .attachment_name()
                .unwrap_or_default()
                .to_string();
            let content_type_str = attachment
                .content_type()
                .map(|ct| ct.ctype().to_string())
                .unwrap_or_default();

            // Dangerous extension check.
            if let Some(ext) = filename.rsplit('.').next() {
                let ext_lower = ext.to_lowercase();
                if self.dangerous_extensions.iter().any(|d| d == &ext_lower) {
                    let score = self.weight * 1.0;
                    total_severity += score;
                    contributions.push(ScoreContribution {
                        check_name: "attachment/dangerous_ext".to_string(),
                        category: CheckCategory::Content,
                        score,
                        description: format!("Dangerous extension: .{} in {}", ext_lower, filename),
                    });
                }
            }

            // Double extension check.
            if self.double_ext_re.is_match(&filename) {
                let score = self.weight * 1.2;
                total_severity += score;
                contributions.push(ScoreContribution {
                    check_name: "attachment/double_ext".to_string(),
                    category: CheckCategory::Content,
                    score,
                    description: format!("Double extension: {}", filename),
                });
            }

            // MIME type mismatch.
            let body = attachment.contents();
            if !content_type_str.is_empty() && !Self::check_magic_bytes(&content_type_str, body) {
                let score = self.weight * 0.8;
                total_severity += score;
                contributions.push(ScoreContribution {
                    check_name: "attachment/mime_mismatch".to_string(),
                    category: CheckCategory::Content,
                    score,
                    description: format!(
                        "MIME type mismatch: {} declared as {}",
                        filename, content_type_str,
                    ),
                });
            }
        }

        if contributions.is_empty() {
            (CheckOutcome::Pass, contributions)
        } else {
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: format!("{} attachment issues", contributions.len()),
                },
                contributions,
            )
        }
    }
}
