use crate::error::Result;
use crate::sanitization::sandbox::{Sandbox, SandboxConfig};
use std::time::Duration;

/// Configuration for isolated subprocess workers.
/// Wraps the sandbox module for backward compatibility.
pub struct WorkerPool {
    #[allow(dead_code)]
    sandbox: Sandbox,
}

impl WorkerPool {
    pub fn new(max_workers: usize) -> Self {
        let config = SandboxConfig {
            enabled: true,
            max_concurrent: max_workers,
            ..Default::default()
        };
        Self {
            sandbox: Sandbox::new(config),
        }
    }

    /// Run a parsing operation in an isolated subprocess.
    pub fn run_isolated(&self, operation: &str, input: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let mut config = SandboxConfig::default();
        config.enabled = true;
        config.timeout_seconds = timeout.as_secs().max(1);
        let sandbox = Sandbox::new(config);
        sandbox.run_worker(operation, input)
    }
}
