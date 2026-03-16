use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::config::schema::ServerWallConfig;
use crate::error::ServerWallError;

/// RAII guard that removes a lock file on drop.
struct LockGuard(PathBuf);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Acquire a per-file lock using a sentinel `.lock` file.
///
/// Creates `{path}.lock` exclusively. Retries up to 5 times with 100ms
/// delay to handle brief concurrent access from CLI and web UI.
fn acquire_lock(config_path: &Path) -> Result<LockGuard, ServerWallError> {
    let lock_path = PathBuf::from(format!("{}.lock", config_path.display()));

    for attempt in 0..5u8 {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_) => return Ok(LockGuard(lock_path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if attempt < 4 {
                    thread::sleep(Duration::from_millis(100));
                }
            }
            Err(e) => {
                return Err(ServerWallError::Io(e));
            }
        }
    }

    Err(ServerWallError::Config(
        "config file is locked by another process".into(),
    ))
}

/// Write a [`ServerWallConfig`] to disk atomically.
///
/// The write happens as:
/// 1. Serialize to TOML.
/// 2. Write to a temporary file in the same directory.
/// 3. `rename()` the temp file to the final path (atomic on Linux).
///
/// A `.lock` sentinel file guards against concurrent writes.
pub fn write_config_atomic(path: &Path, config: &ServerWallConfig) -> Result<(), ServerWallError> {
    let toml_str = toml::to_string_pretty(config)
        .map_err(|e| ServerWallError::Config(format!("failed to serialize config: {}", e)))?;

    let parent = path
        .parent()
        .ok_or_else(|| ServerWallError::Config("config path has no parent directory".into()))?;

    let _lock = acquire_lock(path)?;

    // Write to a temp file in the same directory, then rename atomically.
    let tmp_path = parent.join(format!(
        ".serverwall_cfg_tmp_{}.toml",
        std::process::id()
    ));

    {
        let mut f = std::fs::File::create(&tmp_path)
            .map_err(ServerWallError::Io)?;
        f.write_all(toml_str.as_bytes())
            .map_err(ServerWallError::Io)?;
        f.sync_all().map_err(ServerWallError::Io)?;
    }

    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        ServerWallError::Io(e)
    })?;

    Ok(())
}
