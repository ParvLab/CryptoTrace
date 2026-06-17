use crate::error::Result;
use crate::sanitization::sandbox::SandboxConfig;
use std::time::Duration;

/// Configuration for isolated subprocess workers.
/// Wraps the sandbox module for backward compatibility.
pub struct WorkerPool;

impl WorkerPool {
    pub fn new(_max_workers: usize) -> Self {
        Self
    }

    /// Run a parsing operation in an isolated subprocess.
    pub fn run_isolated(
        &self,
        operation: &str,
        input: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let mut config = SandboxConfig::default();
        config.enabled = true;
        config.timeout_seconds = timeout.as_secs().max(1);
        let sandbox = crate::sanitization::sandbox::Sandbox::new(config);
        sandbox.run_worker(operation, input)
    }
}
