use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use regex::Regex;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Configuration for a single AV scanner.
#[derive(Debug, Clone)]
pub struct ScannerDef {
    pub name: String,
    /// Command template. `{file}` is replaced with the temp file path.
    pub command: String,
    pub clean_exit_codes: Vec<i32>,
    pub virus_exit_codes: Vec<i32>,
    pub virus_name_pattern: Option<Regex>,
}

/// Scans message attachments using an external antivirus scanner command.
pub struct AntivirusCheck {
    pub weight: f64,
    pub reject_on_virus: bool,
    pub scanners: Vec<ScannerDef>,
}

impl AntivirusCheck {
    pub fn new(weight: f64, reject_on_virus: bool, scanners: Vec<ScannerDef>) -> Self {
        Self {
            weight,
            reject_on_virus,
            scanners,
        }
    }
}

#[async_trait]
impl PostDataCheck for AntivirusCheck {
    fn name(&self) -> &str {
        "antivirus"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        if self.scanners.is_empty() {
            return (
                CheckOutcome::Skip {
                    reason: "No AV scanners configured".to_string(),
                },
                Vec::new(),
            );
        }

        // Write message to a temp file.
        let tmp = match NamedTempFile::new() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "failed to create temp file for AV scan");
                return (
                    CheckOutcome::Skip {
                        reason: "temp file creation failed".to_string(),
                    },
                    Vec::new(),
                );
            }
        };

        let tmp_path = tmp.path().to_path_buf();
        if let Err(e) = tokio::fs::write(&tmp_path, &ctx.raw_message).await {
            tracing::warn!(error = %e, "failed to write temp file for AV scan");
            return (
                CheckOutcome::Skip {
                    reason: "temp file write failed".to_string(),
                },
                Vec::new(),
            );
        }

        // Run all scanners in parallel.
        let futures: Vec<_> = self
            .scanners
            .iter()
            .map(|scanner| run_scanner(scanner, &tmp_path))
            .collect();
        let results = futures::future::join_all(futures).await;

        let mut contributions = Vec::new();
        let mut total_severity: f64 = 0.0;
        let mut virus_found = false;

        for (scanner_name, scan_result) in self.scanners.iter().zip(results) {
            match scan_result {
                ScanResult::Clean => {}
                ScanResult::Virus(virus_name) => {
                    virus_found = true;
                    let score = self.weight * 1.0;
                    total_severity += score;
                    contributions.push(ScoreContribution {
                        check_name: "antivirus".to_string(),
                        category: CheckCategory::Content,
                        score,
                        description: "Virus detected".to_string(),
                    });
                }
                ScanResult::Error(e) => {
                    tracing::warn!(scanner = %scanner_name.name, error = %e, "AV scanner error");
                }
            }
        }

        // Clean up temp file (best effort).
        let _ = tokio::fs::remove_file(&tmp_path).await;

        if virus_found && self.reject_on_virus {
            return (
                CheckOutcome::Reject {
                    reason: "Message rejected".to_string(),
                },
                contributions,
            );
        }

        if contributions.is_empty() {
            (CheckOutcome::Pass, contributions)
        } else {
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: "Content rejected".to_string(),
                },
                contributions,
            )
        }
    }
}

enum ScanResult {
    Clean,
    Virus(String),
    Error(String),
}

async fn run_scanner(scanner: &ScannerDef, file_path: &PathBuf) -> ScanResult {
    let file_str = file_path.to_string_lossy();
    let command_line = scanner.command.replace("{file}", &file_str);

    // Split command line into program and args.
    let parts: Vec<&str> = command_line.split_whitespace().collect();
    if parts.is_empty() {
        return ScanResult::Error("empty scanner command".to_string());
    }

    let program = parts[0];
    let args = &parts[1..];

    let output = match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
    {
        Ok(out) => out,
        Err(e) => return ScanResult::Error(format!("failed to run scanner: {}", e)),
    };

    let exit_code = output.status.code().unwrap_or(-1);

    if scanner.clean_exit_codes.contains(&exit_code) {
        return ScanResult::Clean;
    }

    if scanner.virus_exit_codes.contains(&exit_code) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let virus_name = if let Some(ref pattern) = scanner.virus_name_pattern {
            pattern
                .captures(&stdout)
                .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            stdout.lines().next().unwrap_or("unknown").to_string()
        };
        return ScanResult::Virus(virus_name);
    }

    ScanResult::Error(format!("scanner exited with code {}", exit_code))
}
