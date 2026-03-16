use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use chrono::Utc;

use super::message::{Envelope, MessageMetadata, QueueStatus, QueuedMessage};

/// Filesystem-backed message spool.
///
/// Each message is stored as two files:
/// - `<queue_id>.meta` — JSON-serialized `QueuedMessage` (envelope + metadata)
/// - `<queue_id>.msg`  — raw RFC 5322 message bytes
pub struct FilesystemSpool {
    spool_dir: PathBuf,
}

impl FilesystemSpool {
    /// Create a new spool rooted at the given directory.
    /// The directory (and parents) will be created if they do not exist.
    pub fn new(spool_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&spool_dir)
            .with_context(|| format!("failed to create spool directory: {}", spool_dir.display()))?;
        Ok(Self { spool_dir })
    }

    /// Generate a 12-character hex queue ID from current timestamp + random bytes.
    fn generate_queue_id() -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let rand_part: u16 = (uuid::Uuid::new_v4().as_u128() & 0xFFFF) as u16;
        format!("{:08X}{:04X}", ts as u32, rand_part)
    }

    fn meta_path(&self, queue_id: &str) -> PathBuf {
        self.spool_dir.join(format!("{queue_id}.meta"))
    }

    fn msg_path(&self, queue_id: &str) -> PathBuf {
        self.spool_dir.join(format!("{queue_id}.msg"))
    }

    /// Enqueue a message into the spool. Returns the queue ID.
    pub fn enqueue(&self, envelope: Envelope, message: Vec<u8>) -> Result<String> {
        let queue_id = Self::generate_queue_id();
        let now = Utc::now();

        let queued = QueuedMessage {
            id: queue_id.clone(),
            envelope,
            metadata: MessageMetadata {
                created: now,
                next_retry: now,
                attempts: 0,
                last_error: None,
                status: QueueStatus::Pending,
                size: message.len(),
            },
        };

        let meta_json = serde_json::to_string_pretty(&queued)
            .context("failed to serialize queue metadata")?;

        // Write message first, then metadata (meta presence = "committed")
        std::fs::write(self.msg_path(&queue_id), &message)
            .with_context(|| format!("failed to write message file for {queue_id}"))?;
        std::fs::write(self.meta_path(&queue_id), meta_json.as_bytes())
            .with_context(|| format!("failed to write metadata file for {queue_id}"))?;

        tracing::info!(queue_id = %queue_id, size = message.len(), "message enqueued");
        Ok(queue_id)
    }

    /// Dequeue (read) a message and its raw bytes from the spool.
    pub fn dequeue(&self, queue_id: &str) -> Result<(QueuedMessage, Vec<u8>)> {
        let meta_bytes = std::fs::read(self.meta_path(queue_id))
            .with_context(|| format!("failed to read metadata for {queue_id}"))?;
        let queued: QueuedMessage = serde_json::from_slice(&meta_bytes)
            .with_context(|| format!("failed to parse metadata for {queue_id}"))?;
        let msg_bytes = std::fs::read(self.msg_path(queue_id))
            .with_context(|| format!("failed to read message for {queue_id}"))?;
        Ok((queued, msg_bytes))
    }

    /// Remove a message from the spool (both files).
    pub fn remove(&self, queue_id: &str) -> Result<()> {
        let meta = self.meta_path(queue_id);
        let msg = self.msg_path(queue_id);
        if meta.exists() {
            std::fs::remove_file(&meta)
                .with_context(|| format!("failed to remove metadata for {queue_id}"))?;
        }
        if msg.exists() {
            std::fs::remove_file(&msg)
                .with_context(|| format!("failed to remove message for {queue_id}"))?;
        }
        tracing::debug!(queue_id = %queue_id, "message removed from spool");
        Ok(())
    }

    /// List all queued messages (by scanning for .meta files).
    pub fn list(&self) -> Result<Vec<QueuedMessage>> {
        let mut messages = Vec::new();
        let entries = std::fs::read_dir(&self.spool_dir)
            .with_context(|| format!("failed to read spool directory: {}", self.spool_dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("meta") {
                match std::fs::read(&path) {
                    Ok(data) => match serde_json::from_slice::<QueuedMessage>(&data) {
                        Ok(msg) => messages.push(msg),
                        Err(e) => {
                            tracing::warn!(path = %path.display(), error = %e, "corrupt metadata file");
                        }
                    },
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "failed to read metadata file");
                    }
                }
            }
        }

        Ok(messages)
    }

    /// Update the metadata for an existing queued message.
    pub fn update_metadata(&self, queue_id: &str, metadata: &MessageMetadata) -> Result<()> {
        let meta_path = self.meta_path(queue_id);
        let meta_bytes = std::fs::read(&meta_path)
            .with_context(|| format!("failed to read metadata for {queue_id}"))?;
        let mut queued: QueuedMessage = serde_json::from_slice(&meta_bytes)
            .with_context(|| format!("failed to parse metadata for {queue_id}"))?;

        queued.metadata = metadata.clone();

        let updated_json = serde_json::to_string_pretty(&queued)
            .context("failed to serialize updated metadata")?;
        std::fs::write(&meta_path, updated_json.as_bytes())
            .with_context(|| format!("failed to write updated metadata for {queue_id}"))?;

        Ok(())
    }
}
