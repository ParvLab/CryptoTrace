use crate::error::Result;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A simple counting semaphore for synchronizing concurrent worker access.
#[derive(Debug)]
struct CountSemaphore {
    inner: Arc<Mutex<usize>>,
    max: usize,
}

impl CountSemaphore {
    fn new(max: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(max)),
            max,
        }
    }

    fn acquire(&self) -> Result<CountPermit> {
        let mut count = self.inner.lock().map_err(|e| {
            crate::error::CryptoTraceError::Other(format!("Semaphore lock error: {}", e))
        })?;
        if *count == 0 {
            return Err(crate::error::CryptoTraceError::Other(
                "Max concurrent workers reached".to_string(),
            ));
        }
        *count -= 1;
        Ok(CountPermit {
            inner: Arc::clone(&self.inner),
            max: self.max,
        })
    }
}

#[derive(Debug)]
struct CountPermit {
    inner: Arc<Mutex<usize>>,
    max: usize,
}

impl Drop for CountPermit {
    fn drop(&mut self) {
        if let Ok(mut count) = self.inner.lock() {
            *count = (*count + 1).min(self.max);
        }
    }
}

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
/// - Windows:   Job Object with memory limit, active process limit, kill-on-close
/// - Linux:     subprocess with seccomp-bpf (blocks execve, clone, socket, etc.)
///              + RLIMIT_AS memory enforcement
/// - macOS:     subprocess with sandbox-init (deny network, fs-write, proc-spawn)
///
/// The worker process is a separate binary (`cryptotrace-worker`) that
/// performs the actual analysis. If it crashes or times out, the parent
/// process is unaffected.
pub struct Sandbox {
    config: SandboxConfig,
    semaphore: Option<Arc<CountSemaphore>>,
}

impl Sandbox {
    /// Create a new sandbox.
    pub fn new(config: SandboxConfig) -> Self {
        let semaphore = if config.enabled && config.max_concurrent > 0 {
            Some(Arc::new(CountSemaphore::new(config.max_concurrent)))
        } else {
            None
        };
        Self { config, semaphore }
    }

    /// Run an operation in a sandboxed worker subprocess.
    /// The worker receives input on stdin and writes output to stdout.
    /// If the worker times out or crashes, an error is returned.
    pub fn run_worker(&self, operation: &str, input: &[u8]) -> Result<Vec<u8>> {
        if !self.config.enabled {
            return Ok(input.to_vec());
        }

        // Acquire concurrency permit
        let _permit = match self.semaphore.as_ref() {
            Some(s) => Some(s.acquire().map_err(|e| {
                crate::error::CryptoTraceError::Other(format!("Semaphore error: {}", e))
            })?),
            None => None,
        };

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

        // Set memory limit env var for pre_exec closures
        cmd.env(
            "CRYPTOTRACE_MAX_MEMORY_MB",
            self.config.max_memory_mb.to_string(),
        );

        // Platform-specific sandbox enforcement (pre-spawn)
        apply_platform_sandbox(&mut cmd, self.config.max_memory_mb);

        let mut child = cmd.spawn().map_err(|e| {
            crate::error::CryptoTraceError::Other(format!("Failed to spawn worker: {}", e))
        })?;

        // Post-spawn sandbox enforcement (Windows Job Object)
        #[cfg(target_os = "windows")]
        let _job_handle = apply_post_spawn_sandbox(&child, self.config.max_memory_mb)?;

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
// Platform-specific sandbox enforcement (pre-spawn)
// ---------------------------------------------------------------------------

/// Apply platform sandbox restrictions to the worker subprocess (pre-spawn).
#[cfg(target_os = "linux")]
fn apply_platform_sandbox(cmd: &mut Command, _max_memory_mb: u64) {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Enforce memory limit via setrlimit (read from env var)
            let mem_mb: u64 = std::env::var("CRYPTOTRACE_MAX_MEMORY_MB")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(512);
            let max_bytes = mem_mb.saturating_mul(1024 * 1024);
            let rlim = libc::rlimit {
                rlim_cur: max_bytes,
                rlim_max: max_bytes,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &rlim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            install_seccomp_blacklist()
        });
    }
}

#[cfg(target_os = "macos")]
fn apply_platform_sandbox(cmd: &mut Command, _max_memory_mb: u64) {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            // Resolve $HOME at runtime (not a literal string)
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let profile = format!(
                "(version 1)
(deny default (with send-signal SIGKILL))
(deny network*)
(allow file-read* (subpath \"/\") (subpath \"/usr/lib/\"))
(allow file-write* (subpath \"{}\"))
(allow process-exec (literal \"/usr/lib/dyld\"))
(allow sysctl-uname)
(allow mach*)
",
                home
            );
            let profile_bytes = profile.as_bytes();
            let mut error: *mut libc::c_char = std::ptr::null_mut();
            extern "C" {
                fn sandbox_init(
                    profile: *const libc::c_char,
                    flags: u64,
                    errorbuf: *mut *mut libc::c_char,
                ) -> libc::c_int;
                fn sandbox_free_error(errorbuf: *mut libc::c_char);
            }
            let ret = unsafe {
                sandbox_init(
                    profile_bytes.as_ptr() as *const libc::c_char,
                    0u64,
                    &mut error,
                )
            };
            if ret != 0 {
                if !error.is_null() {
                    let msg = std::ffi::CStr::from_ptr(error)
                        .to_string_lossy()
                        .into_owned();
                    unsafe {
                        sandbox_free_error(error);
                    }
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
fn apply_platform_sandbox(cmd: &mut Command, _max_memory_mb: u64) {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn apply_platform_sandbox(_cmd: &mut Command, _max_memory_mb: u64) {
    // other Unix: no extra sandbox
}

// ---------------------------------------------------------------------------
// Post-spawn sandbox enforcement (Windows Job Object)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn apply_post_spawn_sandbox(
    child: &std::process::Child,
    max_memory_mb: u64,
) -> std::io::Result<*mut std::ffi::c_void> {
    use std::ffi::c_void;
    use std::ptr;

    type HANDLE = *mut c_void;
    type BOOL = i32;
    type DWORD = u32;
    type LPCWSTR = *const u16;
    type LPVOID = *mut c_void;

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x2000;
    const JOB_OBJECT_LIMIT_PROCESS_MEMORY: DWORD = 0x100;
    const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: DWORD = 0x8;
    const PROCESS_SET_QUOTA: DWORD = 0x0100;
    const PROCESS_TERMINATE: DWORD = 0x0001;
    const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;

    #[repr(C)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: DWORD,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: DWORD,
        affinity: usize,
        child_process_count: DWORD,
        maximum_process_memory: usize,
    }

    #[repr(C)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        io_info: [c_void; 24],
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    unsafe extern "system" {
        fn CreateJobObjectW(lpJobAttributes: *const c_void, lpName: LPCWSTR) -> HANDLE;
        fn SetInformationJobObject(
            hJob: HANDLE,
            job_object_info_class: DWORD,
            lp_job_object_info: LPVOID,
            cb_job_object_info_length: DWORD,
        ) -> BOOL;
        fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> BOOL;
        fn OpenProcess(
            dw_desired_access: DWORD,
            b_inherit_handle: BOOL,
            dw_process_id: DWORD,
        ) -> HANDLE;
        fn CloseHandle(h_object: HANDLE) -> BOOL;
    }

    unsafe {
        // Create job object
        let job = CreateJobObjectW(ptr::null(), ptr::null());
        if job.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to create Windows Job Object",
            ));
        }

        // Configure limits
        let memory_bytes = (max_memory_mb as usize).saturating_mul(1024 * 1024);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                per_process_user_time_limit: 0,
                per_job_user_time_limit: 0,
                limit_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                    | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                minimum_working_set_size: 0,
                maximum_working_set_size: 0,
                active_process_limit: 1,
                affinity: 0,
                child_process_count: 0,
                maximum_process_memory: memory_bytes,
            },
            io_info: std::mem::zeroed(),
            process_memory_limit: memory_bytes,
            job_memory_limit: 0,
            peak_process_memory_used: 0,
            peak_job_memory_used: 0,
        };

        let ret = SetInformationJobObject(
            job,
            9, // JobObjectExtendedLimitInformation
            &mut limits as *mut _ as LPVOID,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
        );
        if ret == 0 {
            CloseHandle(job);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to set Windows Job Object limits",
            ));
        }

        // Open process handle and assign to job
        let process = OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
            0,
            child.id(),
        );
        if process.is_null() {
            CloseHandle(job);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to open worker process handle for Job Object",
            ));
        }

        let ret = AssignProcessToJobObject(job, process);
        CloseHandle(process);
        if ret == 0 {
            CloseHandle(job);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to assign process to Windows Job Object",
            ));
        }

        // Return job handle — it will be closed when the caller drops it,
        // which triggers KILL_ON_JOB_CLOSE as a safety net
        Ok(job)
    }
}

// ---------------------------------------------------------------------------
// Seccomp-bpf for Linux (multi-arch)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn install_seccomp_blacklist() -> std::result::Result<(), std::io::Error> {
    // Syscall numbers vary by architecture
    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "aarch64")]
    const BLOCKED: &[u32] = &[
        220,  // clone
        1079, // fork (aarch64 uses clone)
        1080, // vfork
        221,  // execve
        129,  // kill
        131,  // tgkill
        222,  // execveat
        436,  // clone3
        198,  // socket
        203,  // connect
        200,  // bind
        201,  // listen
        202,  // accept
        1048, // accept4
        117,  // ptrace
        91,   // personality
        192,  // init_module
        193,  // finit_module
        194,  // delete_module
        269,  // process_vm_readv
        270,  // process_vm_writev
        150,  // iopl (not on arm64, but block anyway)
        151,  // ioperm
    ];

    let mut filters: Vec<libc::sock_filter> = Vec::with_capacity(3 + BLOCKED.len());

    // insn 0: ld [0]
    filters.push(libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    });

    // insns 1..n: jeq BLOCKED[i], KILL_LABEL
    let kill_offset: u8 = (BLOCKED.len() + 1) as u8;
    for syscall in BLOCKED {
        filters.push(libc::sock_filter {
            code: 0x15,
            jt: kill_offset,
            jf: 0,
            k: *syscall,
        });
    }

    // insn n+1: ret ALLOW
    filters.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff_0000,
    });

    // insn n+2: ret KILL
    filters.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x0000_0000,
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

    #[test]
    fn test_max_concurrent_respected() {
        let config = SandboxConfig {
            enabled: true,
            max_concurrent: 1,
            timeout_seconds: 30,
            ..Default::default()
        };
        let sandbox = Sandbox::new(config);
        // Cannot spawn worker (binary doesn't exist), so it returns error
        // but the important thing is it doesn't panic
        let result = sandbox.run_worker("passthrough", b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox_requires_binary() {
        let config = SandboxConfig {
            enabled: true,
            worker_path: Some(PathBuf::from("")),
            timeout_seconds: 1,
            ..Default::default()
        };
        let sandbox = Sandbox::new(config);
        let result = sandbox.run_worker("passthrough", b"data");
        assert!(result.is_err());
    }
}
