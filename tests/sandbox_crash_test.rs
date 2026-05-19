/// Verify that a worker process crash does NOT crash the main process.
///
/// The sandbox runs worker operations in a subprocess. If the worker binary
/// is missing or crashes, the parent process should catch the error and
/// continue — not panic or abort.
///
/// This test:
///   1. Enables sandbox with a path to a nonexistent worker binary
///   2. Calls `run_worker` which should fail gracefully
///   3. Confirms the error is a `CryptoTraceError`, not a panic

use cryptotrace::sanitization::sandbox::{Sandbox, SandboxConfig};
use std::path::PathBuf;

#[test]
fn test_worker_crash_does_not_crash_parent() {
    let config = SandboxConfig {
        enabled: true,
        worker_path: Some(PathBuf::from("this-worker-does-not-exist")),
        timeout_seconds: 1,
        ..Default::default()
    };
    let sandbox = Sandbox::new(config);
    let result = sandbox.run_worker("passthrough", b"test data");

    match result {
        Err(e) => {
            // Expected: the error message should mention the missing worker.
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("worker") || msg.contains("spawn") || msg.contains("not found"),
                "expected worker/spawn/not-found error, got: {}",
                msg
            );
        }
        Ok(_) => panic!("expected sandbox to fail with missing worker binary"),
    }
}

#[test]
fn test_sandbox_disabled_skips_worker() {
    // When sandbox is disabled, run_worker should pass through the input
    // without spawning any process — truly crash-proof.
    let config = SandboxConfig {
        enabled: false,
        ..Default::default()
    };
    let sandbox = Sandbox::new(config);
    let input = b"some payload data";
    let result = sandbox.run_worker("passthrough", input).unwrap();
    assert_eq!(result, input);
}
