use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::types::DetectionResult;

/// Job status enum.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

/// A submitted analysis job.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Job {
    pub id: u64,
    pub status: JobStatus,
    pub input: String,
    pub input_type: String,
    pub context: String,
    pub deep: bool,
    pub ai: bool,
    pub sandbox: bool,
    pub created_at: String,
    pub updated_at: String,
    pub result: Option<DetectionResult>,
}

/// Shared job queue state with optional disk persistence.
pub struct JobQueue {
    next_id: AtomicU64,
    jobs: RwLock<HashMap<u64, Job>>,
    max_concurrent: usize,
    running_count: AtomicU64,
    jobs_dir: Option<PathBuf>,
}

impl JobQueue {
    fn default_jobs_dir() -> PathBuf {
        // Use APPDATA on Windows, XDG_DATA_HOME or ~/.local/share on Unix
        let base = if cfg!(target_os = "windows") {
            std::env::var("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
        } else {
            std::env::var("XDG_DATA_HOME")
                .map(PathBuf::from)
                .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".local").join("share")))
                .unwrap_or_else(|_| PathBuf::from("."))
        };
        base.join("cryptotrace").join("jobs")
    }

    /// Create a new job queue. Jobs are persisted to the default directory.
    pub fn new(max_concurrent: usize) -> Arc<Self> {
        Self::with_persistence(max_concurrent, Self::default_jobs_dir())
    }

    /// Create a new job queue with a specific persistence directory.
    /// Jobs will be loaded from disk on startup and persisted on every change.
    /// Pass `None` for in-memory-only mode (useful in tests).
    pub fn with_persistence(max_concurrent: usize, jobs_dir: impl Into<Option<PathBuf>>) -> Arc<Self> {
        let jobs_dir: Option<PathBuf> = jobs_dir.into();

        // Recover next_id from disk before constructing
        let start_id = if let Some(ref dir) = jobs_dir {
            if dir.exists() {
                Self::recover_max_id(dir) + 1
            } else {
                1
            }
        } else {
            1
        };

        let queue = Arc::new(Self {
            next_id: AtomicU64::new(start_id),
            jobs: RwLock::new(HashMap::new()),
            max_concurrent,
            running_count: AtomicU64::new(0),
            jobs_dir: jobs_dir.clone(),
        });

        // Load jobs asynchronously if directory exists
        if let Some(ref dir) = jobs_dir {
            if dir.exists() {
                let q = queue.clone();
                let d = dir.clone();
                tokio::spawn(async move {
                    q.load_jobs_async(&d).await;
                });
            }
        }

        queue
    }

    fn recover_max_id(dir: &Path) -> u64 {
        let mut max_id = 0u64;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(rest) = name.strip_prefix("job_").and_then(|s| s.strip_suffix(".json")) {
                    if let Ok(id) = rest.parse::<u64>() {
                        max_id = max_id.max(id);
                    }
                }
            }
        }
        max_id
    }

    /// Load persisted jobs from disk (async, runs on startup).
    async fn load_jobs_async(self: &Arc<Self>, dir: &Path) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let mut loaded: HashMap<u64, Job> = HashMap::new();
        let mut max_id: u64 = 0;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(job) = serde_json::from_str::<Job>(&content) {
                    if job.status != JobStatus::Completed
                        && job.status != JobStatus::Failed(String::new())
                        && job.status != JobStatus::Cancelled
                    {
                        // Reset running jobs back to pending on restart
                        let mut restored = job.clone();
                        if restored.status == JobStatus::Running {
                            restored.status = JobStatus::Pending;
                            restored.updated_at = chrono_now();
                            let _ = save_job_to_disk(&path, &restored);
                        }
                        loaded.insert(restored.id, restored);
                    }
                    max_id = max_id.max(job.id);
                }
            }
        }

        let count = loaded.len();
        if count > 0 || max_id > 0 {
            let mut jobs = self.jobs.write().await;
            for (id, job) in &loaded {
                jobs.entry(*id).or_insert_with(|| job.clone());
            }
            if max_id >= self.next_id.load(Ordering::SeqCst) {
                self.next_id.store(max_id + 1, Ordering::SeqCst);
            }
            tracing::info!("Restored {} jobs from disk (next_id: {})", count, max_id + 1);
        }
    }

    /// Path to the JSON file for a given job ID.
    fn job_path(&self, id: u64) -> Option<PathBuf> {
        self.jobs_dir.as_ref().map(|dir| dir.join(format!("job_{}.json", id)))
    }

    /// Persist a job to disk. Synchronous — called after writes.
    fn persist_job(&self, job: &Job) {
        if let Some(path) = self.job_path(job.id) {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = save_job_to_disk(&path, job);
        }
    }

    /// Remove a job's disk file.
    fn remove_job_file(&self, id: u64) {
        if let Some(path) = self.job_path(id) {
            let _ = std::fs::remove_file(&path);
        }
    }

    /// Submit a new job and return its ID.
    pub async fn submit(&self, input: String, input_type: String, context: String, deep: bool, ai: bool, sandbox: bool) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let now = chrono_now();
        let job = Job {
            id,
            status: JobStatus::Pending,
            input,
            input_type,
            context,
            deep,
            ai,
            sandbox,
            created_at: now.clone(),
            updated_at: now,
            result: None,
        };
        self.persist_job(&job);
        self.jobs.write().await.insert(id, job);
        id
    }

    /// Get a job by ID.
    pub async fn get(&self, id: u64) -> Option<Job> {
        self.jobs.read().await.get(&id).cloned()
    }

    /// Cancel a job by ID.
    pub async fn cancel(&self, id: u64) -> Option<Job> {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(&id) {
            if job.status == JobStatus::Pending || job.status == JobStatus::Running {
                job.status = JobStatus::Cancelled;
                job.updated_at = chrono_now();
                self.persist_job(job);
            }
        }
        jobs.get(&id).cloned()
    }

    /// Remove a completed/failed/cancelled job from memory and disk.
    pub async fn remove(&self, id: u64) -> bool {
        self.remove_job_file(id);
        self.jobs.write().await.remove(&id).is_some()
    }

    /// Try to dispatch the next pending job. Returns true if a job was started.
    async fn dispatch_one(self: Arc<Self>) -> bool {
        let running = self.running_count.load(Ordering::SeqCst) as usize;
        if running >= self.max_concurrent {
            return false;
        }

        let next_id = {
            let jobs = self.jobs.read().await;
            jobs.iter()
                .find(|(_, j)| j.status == JobStatus::Pending)
                .map(|(id, _)| *id)
        };

        let id = match next_id {
            Some(id) => id,
            None => return false,
        };

        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&id) {
                if job.status != JobStatus::Pending {
                    return false;
                }
                job.status = JobStatus::Running;
                job.updated_at = chrono_now();
                self.persist_job(job);
            }
        }

        self.running_count.fetch_add(1, Ordering::SeqCst);

        let job_snapshot = {
            let jobs = self.jobs.read().await;
            jobs.get(&id).cloned()
        };

        if let Some(job_data) = job_snapshot {
            let queue = self.clone();
            let queue_clone = queue.clone();
            tokio::spawn(async move {
                queue_clone.run_job(job_data).await;
                queue.running_count.fetch_sub(1, Ordering::SeqCst);
            });
            true
        } else {
            false
        }
    }

    /// Start a background worker that polls for pending jobs.
    pub fn start_worker(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = self.clone().dispatch_one().await;
            }
        });
    }

    /// Start a background cleanup task that removes jobs older than 24 hours.
    pub fn start_cleanup(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let cutoff = now.saturating_sub(86400); // 24 hours

                let to_remove: Vec<u64> = {
                    let jobs = self.jobs.read().await;
                    jobs.iter()
                        .filter(|(_, j)| {
                            // Parse the updated_at timestamp
                            let ts = j.updated_at.split('.').next()
                                .and_then(|s| s.parse::<u64>().ok())
                                .unwrap_or(0);
                            ts < cutoff && (j.status == JobStatus::Completed
                                || matches!(j.status, JobStatus::Failed(_))
                                || j.status == JobStatus::Cancelled)
                        })
                        .map(|(id, _)| *id)
                        .collect()
                };

                let remove_count = to_remove.len();
                for id in to_remove {
                    self.remove(id).await;
                }
                if remove_count > 0 {
                    tracing::info!("Cleaned up {} expired jobs", remove_count);
                }
            }
        });
    }

    async fn run_job(self: Arc<Self>, job: Job) {
        let id = job.id;
        let result = crate::api::routes::run_analysis(
            &job.input,
            &job.input_type,
            &job.context,
            job.deep,
            job.ai,
            job.sandbox,
        ).await;

        let mut jobs = self.jobs.write().await;
        if let Some(entry) = jobs.get_mut(&id) {
            match result {
                Ok(detection) => {
                    entry.status = JobStatus::Completed;
                    entry.result = Some(detection);
                }
                Err(e) => {
                    entry.status = JobStatus::Failed(format!("{:?}", e));
                }
            }
            entry.updated_at = chrono_now();
            self.persist_job(entry);
        }
    }
}

/// Save a job as JSON to disk. Called synchronously from write paths.
fn save_job_to_disk(path: &Path, job: &Job) -> Result<(), String> {
    let json = serde_json::to_string_pretty(job).map_err(|e| e.to_string())?;
    std::fs::write(path, &json).map_err(|e| e.to_string())?;
    Ok(())
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    format!("{}.{:03}", secs, millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_queue() -> Arc<JobQueue> {
        let dir = TempDir::new().unwrap();
        JobQueue::with_persistence(4, Some(dir.path().to_path_buf()))
    }

    #[tokio::test]
    async fn test_submit_and_get() {
        let queue = test_queue();
        let id = queue.submit(
            "test".to_string(),
            "string".to_string(),
            "forensics".to_string(),
            false,
            false,
            false,
        ).await;
        let job = queue.get(id).await.unwrap();
        assert_eq!(job.status, JobStatus::Pending);
        assert_eq!(job.input, "test");
    }

    #[tokio::test]
    async fn test_cancel_pending() {
        let queue = test_queue();
        let id = queue.submit("data".to_string(), "string".to_string(), "forensics".to_string(), false, false, false).await;
        let cancelled = queue.cancel(id).await.unwrap();
        assert_eq!(cancelled.status, JobStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_remove() {
        let queue = test_queue();
        let id = queue.submit("data".to_string(), "string".to_string(), "forensics".to_string(), false, false, false).await;
        assert!(queue.remove(id).await);
        assert!(queue.get(id).await.is_none());
    }

    #[tokio::test]
    async fn test_persistence_survives_restart() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();

        // Create first queue instance and submit a job
        let id = {
            let queue = JobQueue::with_persistence(4, Some(path.clone()));
            let id = queue.submit("persist-test".to_string(), "string".to_string(), "forensics".to_string(), false, false, false).await;
            // Give time for the initial load to settle
            tokio::time::sleep(Duration::from_millis(100)).await;
            id
        };

        // Drop first instance (queue goes out of scope)
        // Create second instance — should load job from disk
        tokio::time::sleep(Duration::from_millis(200)).await;
        let queue2 = JobQueue::with_persistence(4, Some(path.clone()));
        tokio::time::sleep(Duration::from_millis(500)).await;

        let job = queue2.get(id).await;
        assert!(job.is_some(), "Job should persist across restarts");
        if let Some(j) = job {
            assert_eq!(j.input, "persist-test");
        }
    }

    #[tokio::test]
    async fn test_in_memory_mode() {
        let queue = JobQueue::with_persistence(4, None::<PathBuf>);
        let id = queue.submit("mem-only".to_string(), "string".to_string(), "forensics".to_string(), false, false, false).await;
        let job = queue.get(id).await.unwrap();
        assert_eq!(job.input, "mem-only");
    }
}
