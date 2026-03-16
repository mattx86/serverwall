use std::path::Path;

use crate::error::{Result, ServerWallError};

/// Send SIGHUP to the serverwall daemon to trigger a config reload.
///
/// Reads the PID from `pid_file` and sends SIGHUP. On non-Unix platforms
/// this is a no-op (the daemon uses file-watch reload instead).
pub fn send_reload_signal(pid_file: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let content = std::fs::read_to_string(pid_file).map_err(|e| {
            ServerWallError::Config(format!(
                "failed to read PID file {}: {}",
                pid_file.display(),
                e
            ))
        })?;

        let pid: libc::pid_t = content.trim().parse().map_err(|_| {
            ServerWallError::Config(format!(
                "invalid PID in {}: {:?}",
                pid_file.display(),
                content.trim()
            ))
        })?;

        // SAFETY: kill(2) is safe to call with a valid pid and SIGHUP.
        let result = unsafe { libc::kill(pid, libc::SIGHUP) };
        if result != 0 {
            return Err(ServerWallError::Io(std::io::Error::last_os_error()));
        }

        tracing::debug!(pid = pid, "sent SIGHUP to serverwall daemon");
    }

    #[cfg(not(unix))]
    {
        let _ = pid_file;
        tracing::debug!("reload signal not supported on this platform");
    }

    Ok(())
}
