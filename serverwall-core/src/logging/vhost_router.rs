use std::collections::HashMap;
use std::path::PathBuf;

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

/// Routes log output to per-frontend (vhost) log files using non-blocking appenders.
///
/// Each frontend gets its own log file in the configured log directory.
/// Uses `tracing_appender::non_blocking` for async log writing to avoid
/// blocking the event loop on I/O.
pub struct VhostLogRouter {
    /// Base directory for vhost log files.
    log_dir: PathBuf,
    /// Map of frontend_name -> (non-blocking writer, worker guard).
    /// The WorkerGuard must be kept alive for the duration of logging;
    /// dropping it flushes and stops the background writer thread.
    writers: HashMap<String, (NonBlocking, WorkerGuard)>,
}

impl VhostLogRouter {
    /// Create a new vhost log router that writes log files into `log_dir`.
    pub fn new(log_dir: PathBuf) -> Self {
        Self {
            log_dir,
            writers: HashMap::new(),
        }
    }

    /// Register a frontend for logging. Creates a log file appender
    /// for `<log_dir>/<frontend_name>.log`.
    pub fn add_vhost(&mut self, frontend_name: impl Into<String>) {
        let name: String = frontend_name.into();
        if self.writers.contains_key(&name) {
            return;
        }

        let file_appender = tracing_appender::rolling::never(&self.log_dir, format!("{}.log", name));
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        self.writers.insert(name, (non_blocking, guard));
    }

    /// Write a log line to the log file for the given frontend.
    /// If the frontend has not been registered, the line is silently dropped.
    pub fn write_line(&self, frontend_name: &str, line: &str) {
        if let Some((writer, _guard)) = self.writers.get(frontend_name) {
            use std::io::Write;
            // NonBlocking implements std::io::Write
            let mut w = writer.clone();
            let _ = writeln!(w, "{}", line);
        }
    }

    /// Get the log file path for a frontend.
    pub fn get_log_path(&self, frontend_name: &str) -> Option<PathBuf> {
        if self.writers.contains_key(frontend_name) {
            Some(self.log_dir.join(format!("{}.log", frontend_name)))
        } else {
            None
        }
    }

    /// List all registered frontend names.
    pub fn registered_vhosts(&self) -> Vec<&str> {
        self.writers.keys().map(|s| s.as_str()).collect()
    }
}
