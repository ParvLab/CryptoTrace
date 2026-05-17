use crate::error::Result;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Sandbox configuration for untrusted binary analysis.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub enabled: bool,
    pub worker_path: Option<PathBuf>,
    pub timeout_seconds: u64,
    pub max_memory_mb: u64,
    pub max_concurrent: usize,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            worker_path: None,
            timeout_seconds: 30,
            max_memory_mb: 512,
            max_concurrent: 4,
        }
    }
}

/// Platform-independent sandbox for isolating risky parser operations in a
/// subprocess with timeout and crash recovery.
///
/// - Windows: subprocess with CREATE_NO_WINDOW + timeout + kill-on-fallback
/// - Unix:    subprocess with timeout default
///
/// The worker process is a separate binary (`cryptotrace-worker`) that
/// performs the actual analysis. If it crashes or times out, the parent
/// process is unaffected.
pub struct Sandbox {
    config: SandboxConfig,
}

impl Sandbox {
    /// Create a new sandbox.
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Run an operation in a sandboxed worker subprocess.
    /// The worker receives input on stdin and writes output to stdout.
    /// If the worker times out or crashes, an error is returned.
    pub fn run_worker(&self, operation: &str, input: &[u8]) -> Result<Vec<u8>> {
        if !self.config.enabled {
            return Ok(input.to_vec());
        }

        let worker_exe = self
            .config
            .worker_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("cryptotrace-worker"));

        let mut cmd = Command::new(&worker_exe);

        cmd.arg("--operation")
            .arg(operation)
            .arg("--input-len")
            .arg(input.len().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        let mut child = cmd.spawn().map_err(|e| {
            crate::error::CryptoTraceError::Other(format!("Failed to spawn worker: {}", e))
        })?;

        // Write input to worker stdin (in a background thread to avoid deadlock
        // if the worker's stdout buffer fills up)
        let input_owned = input.to_vec();
        let stdin = child.stdin.take();
        let writer = std::thread::spawn(move || {
            if let Some(mut s) = stdin {
                use std::io::Write;
                let _ = s.write_all(&input_owned);
                let _ = s.flush();
                // Drop s to close stdin
            }
        });

        // Wait for completion with hard timeout
        let timeout = Duration::from_secs(self.config.timeout_seconds);
        let output = Self::wait_with_timeout(child, timeout)?;

        // Ensure stdin writer has finished
        let _ = writer.join();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(crate::error::CryptoTraceError::Other(format!(
                "Worker '{}' failed: {}",
                operation,
                if stderr.is_empty() {
                    format!("exit code: {:?}", output.status.code())
                } else {
                    stderr
                }
            )));
        }

        Ok(output.stdout)
    }

    /// Wait for a child process with a hard timeout.
    /// Polls at 50ms intervals. Kills the process on timeout.
    fn wait_with_timeout(
        mut child: std::process::Child,
        timeout: Duration,
    ) -> Result<std::process::Output> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(50);

        loop {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    // Process has exited — collect remaining output
                    return child.wait_with_output().map_err(|e| {
                        crate::error::CryptoTraceError::Other(format!(
                            "Failed to collect worker output: {}",
                            e
                        ))
                    });
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(crate::error::CryptoTraceError::Other(format!(
                            "Worker timed out after {}s",
                            timeout.as_secs()
                        )));
                    }
                    std::thread::sleep(poll_interval);
                }
                Err(e) => {
                    return Err(crate::error::CryptoTraceError::Other(format!(
                        "Worker wait error: {}",
                        e
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_disabled_passthrough() {
        let config = SandboxConfig {
            enabled: false,
            ..Default::default()
        };
        let sandbox = Sandbox::new(config);
        let input = b"test data";
        let result = sandbox.run_worker("passthrough", input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn test_sandbox_enabled_worker_not_found() {
        let config = SandboxConfig {
            enabled: true,
            worker_path: Some(PathBuf::from("nonexistent-worker.exe")),
            timeout_seconds: 1,
            ..Default::default()
        };
        let sandbox = Sandbox::new(config);
        let result = sandbox.run_worker("passthrough", b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_defaults() {
        let config = SandboxConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.max_memory_mb, 512);
        assert_eq!(config.max_concurrent, 4);
    }
}
