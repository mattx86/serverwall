use std::path::Path;

use clap::{Args, Subcommand};

use serverwall_core::config::load_config;
use serverwall_relay::queue::{FilesystemSpool, QueueStatus};

use crate::output;

#[derive(Args)]
pub struct QueueArgs {
    #[command(subcommand)]
    pub action: QueueAction,

    /// Output as JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum QueueAction {
    /// List queued messages.
    List {
        /// Filter by status (pending, deferred, held, active).
        #[arg(long)]
        status: Option<String>,
        /// Filter by sender.
        #[arg(long)]
        sender: Option<String>,
    },
    /// Delete a queued message.
    Delete {
        /// Message ID.
        id: String,
    },
    /// Retry delivery of a specific deferred message.
    Retry {
        /// Message ID.
        id: String,
    },
    /// Hold a specific message (suspend delivery).
    Hold {
        /// Message ID.
        id: String,
    },
    /// Release a held message back to pending.
    Release {
        /// Message ID.
        id: String,
    },
    /// Flush all deferred messages for immediate delivery.
    Flush,
    /// Show queue statistics.
    Stats,
}

pub fn run(config_path: &Path, args: QueueArgs) -> anyhow::Result<()> {
    let config = load_config(config_path)?;
    let spool = FilesystemSpool::new(config.relay.spool_dir.clone())
        .map_err(|e| anyhow::anyhow!("failed to open spool: {}", e))?;

    match args.action {
        QueueAction::List { status, sender } => {
            let messages = spool.list().unwrap_or_default();
            let messages: Vec<_> = messages.into_iter()
                .filter(|m| {
                    if let Some(ref s) = status {
                        let ms = format!("{:?}", m.metadata.status).to_lowercase();
                        if ms != s.to_lowercase() { return false; }
                    }
                    if let Some(ref from) = sender {
                        if !m.envelope.mail_from.contains(from.as_str()) { return false; }
                    }
                    true
                })
                .collect();

            if args.json {
                let json: Vec<_> = messages.iter().map(|m| serde_json::json!({
                    "id": m.metadata.message_id,
                    "sender": m.envelope.mail_from,
                    "recipients": m.envelope.rcpt_to,
                    "status": format!("{:?}", m.metadata.status).to_lowercase(),
                    "size": m.metadata.size,
                    "attempts": m.metadata.attempts,
                    "created": m.metadata.created.to_rfc3339(),
                })).collect();
                println!("{}", serde_json::to_string_pretty(&json)?);
                return Ok(());
            }

            println!("Total messages: {}\n", messages.len());
            let rows: Vec<Vec<String>> = messages.iter().map(|m| vec![
                m.metadata.message_id.to_string(),
                m.envelope.mail_from.clone(),
                m.envelope.rcpt_to.join(", "),
                format!("{:?}", m.metadata.status).to_lowercase(),
                format_size(m.metadata.size),
                m.metadata.attempts.to_string(),
            ]).collect();
            output::print_table(&["ID", "SENDER", "RECIPIENTS", "STATUS", "SIZE", "ATTEMPTS"], &rows);
        }

        QueueAction::Delete { id } => {
            let id = parse_uuid(&id)?;
            spool.remove(id).map_err(|e| anyhow::anyhow!("failed to delete: {}", e))?;
            println!("Message {} deleted.", id);
        }

        QueueAction::Retry { id } => {
            let id = parse_uuid(&id)?;
            let mut msg = spool.get(id).map_err(|e| anyhow::anyhow!("{}", e))?;
            msg.metadata.status = QueueStatus::Pending;
            msg.metadata.next_retry = Some(chrono::Utc::now());
            spool.update_metadata(id, msg.metadata).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Message {} queued for immediate retry.", id);
        }

        QueueAction::Hold { id } => {
            let id = parse_uuid(&id)?;
            let mut msg = spool.get(id).map_err(|e| anyhow::anyhow!("{}", e))?;
            msg.metadata.status = QueueStatus::Held;
            spool.update_metadata(id, msg.metadata).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Message {} held.", id);
        }

        QueueAction::Release { id } => {
            let id = parse_uuid(&id)?;
            let mut msg = spool.get(id).map_err(|e| anyhow::anyhow!("{}", e))?;
            msg.metadata.status = QueueStatus::Pending;
            spool.update_metadata(id, msg.metadata).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Message {} released to pending.", id);
        }

        QueueAction::Flush => {
            let messages = spool.list().unwrap_or_default();
            let mut count = 0usize;
            for msg in &messages {
                if matches!(msg.metadata.status, QueueStatus::Deferred) {
                    let id = msg.metadata.message_id;
                    let mut updated = msg.clone();
                    updated.metadata.status = QueueStatus::Pending;
                    updated.metadata.next_retry = Some(chrono::Utc::now());
                    let _ = spool.update_metadata(id, updated.metadata);
                    count += 1;
                }
            }
            println!("Flushed {} deferred messages.", count);
        }

        QueueAction::Stats => {
            let messages = spool.list().unwrap_or_default();
            let total = messages.len();
            let pending = messages.iter().filter(|m| matches!(m.metadata.status, QueueStatus::Pending)).count();
            let deferred = messages.iter().filter(|m| matches!(m.metadata.status, QueueStatus::Deferred)).count();
            let held = messages.iter().filter(|m| matches!(m.metadata.status, QueueStatus::Held)).count();
            let active = messages.iter().filter(|m| matches!(m.metadata.status, QueueStatus::Active)).count();

            if args.json {
                let json = serde_json::json!({
                    "total": total, "pending": pending,
                    "deferred": deferred, "held": held, "active": active,
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
                return Ok(());
            }

            println!("Queue Statistics");
            println!("================");
            println!("Total:    {}", total);
            println!("Pending:  {}", pending);
            println!("Deferred: {}", deferred);
            println!("Held:     {}", held);
            println!("Active:   {}", active);
        }
    }
    Ok(())
}

fn parse_uuid(s: &str) -> anyhow::Result<uuid::Uuid> {
    uuid::Uuid::parse_str(s).map_err(|_| anyhow::anyhow!("invalid message ID: {}", s))
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    }
}
