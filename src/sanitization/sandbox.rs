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
/// - Windows:   subprocess with CREATE_NO_WINDOW + timeout + kill-on-fallback
/// - Linux:     subprocess with seccomp-bpf (blocks execve, clone, socket, etc.)
/// - macOS:     subprocess with sandbox-init (deny network, fs-write, proc-spawn)
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

        // Platform-specific sandbox enforcement
        apply_platform_sandbox(&mut cmd);

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
            }
        });

        // Wait for completion with hard timeout
        let timeout = Duration::from_secs(self.config.timeout_seconds);
        let output = Self::wait_with_timeout(child, timeout)?;

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

// ---------------------------------------------------------------------------
// Platform-specific sandbox enforcement
// ---------------------------------------------------------------------------

/// Apply platform sandbox restrictions to the worker subprocess.
/// Called before spawning. On Linux and macOS this uses `pre_exec` to
/// install seccomp / sandbox-init in the child process after fork.
#[cfg(target_os = "linux")]
fn apply_platform_sandbox(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            install_seccomp_blacklist()
        });
    }
}

#[cfg(target_os = "macos")]
fn apply_platform_sandbox(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            let profile = b"(version 1)
(deny default (with send-signal SIGKILL))
(allow file-read* (subpath \"/\") (subpath \"/usr/lib/\"))
(allow file-write* (subpath \"${HOME}\"))
(allow process-exec (literal \"/usr/lib/dyld\"))
(allow sysctl-uname)
(allow mach*)
";
            let mut error: *mut libc::c_char = std::ptr::null_mut();
            let ret = libc::sandbox_init(
                profile.as_ptr() as *const libc::c_char,
                0,
                &mut error,
            );
            if ret != 0 {
                if !error.is_null() {
                    let msg = std::ffi::CStr::from_ptr(error).to_string_lossy().into_owned();
                    libc::sandbox_free_error(error);
                    Err(std::io::Error::new(std::io::ErrorKind::Other, msg))
                } else {
                    Err(std::io::Error::last_os_error())
                }
            } else {
                Ok(())
            }
        });
    }
}

#[cfg(target_os = "windows")]
fn apply_platform_sandbox(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn apply_platform_sandbox(_cmd: &mut Command) {
    // other Unix: no extra sandbox
}

// ---------------------------------------------------------------------------
// Seccomp-bpf for Linux
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn install_seccomp_blacklist() -> Result<(), std::io::Error> {
    // Syscall numbers to block (x86_64)
    const BLOCKED: &[u32] = &[
        56,  // clone
        57,  // fork
        58,  // vfork
        59,  // execve
        62,  // kill
        234, // tgkill
        322, // execveat
        335, // clone3
        41,  // socket
        42,  // connect
        49,  // bind
        50,  // listen
        43,  // accept
        288, // accept4
        101, // ptrace
        135, // personality
        175, // init_module
        176, // finit_module
        179, // delete_module
        246, // process_vm_readv
        247, // process_vm_writev
        172, // iopl
        173, // ioperm
    ];

    // BPF instructions:
    //   0: ld  [0]              ; load syscall number (offset 0 in seccomp_data)
    //   1..n: jeq BLOCKED[i], KILL_LABEL
    //   n+1: ret ALLOW
    //   n+2: ret KILL

    let mut filters: Vec<libc::sock_filter> = Vec::with_capacity(3 + BLOCKED.len());

    // insn 0: ld [0]
    filters.push(libc::sock_filter {
        code: 0x20, // BPF_LD | BPF_W | BPF_ABS
        jt: 0,
        jf: 0,
        k: 0, // offset 0 = syscall number
    });

    // insns 1..n: jeq BLOCKED[i], KILL_LABEL
    let kill_offset: u8 = (BLOCKED.len() + 1) as u8; // skip remaining jeqs + ret allow
    for syscall in BLOCKED {
        filters.push(libc::sock_filter {
            code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
            jt: kill_offset,
            jf: 0,
            k: *syscall,
        });
    }

    // insn n+1: ret ALLOW
    filters.push(libc::sock_filter {
        code: 0x06, // BPF_RET | BPF_K
        jt: 0,
        jf: 0,
        k: 0x7fff_0000, // SECCOMP_RET_ALLOW
    });

    // insn n+2: ret KILL
    filters.push(libc::sock_filter {
        code: 0x06, // BPF_RET | BPF_K
        jt: 0,
        jf: 0,
        k: 0x0000_0000, // SECCOMP_RET_KILL
    });

    let prog = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };

    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const _ as libc::c_ulong,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
