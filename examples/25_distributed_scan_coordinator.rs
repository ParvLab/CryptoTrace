use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

#[derive(Debug, Clone)]
struct ScanJob {
    id: usize,
    data: Vec<u8>,
    status: String,
    result: Option<String>,
    duration_ms: u64,
}

struct Coordinator {
    jobs: Arc<Mutex<Vec<ScanJob>>>,
    next_id: AtomicUsize,
    completed: Arc<AtomicUsize>,
    max_workers: usize,
}

impl Coordinator {
    fn new(max_workers: usize) -> Self {
        Coordinator {
            jobs: Arc::new(Mutex::new(Vec::new())),
            next_id: AtomicUsize::new(1),
            completed: Arc::new(AtomicUsize::new(0)),
            max_workers,
        }
    }

    fn submit(&self, data: Vec<u8>) -> usize {
        let mut jobs = self.jobs.lock().unwrap();
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        jobs.push(ScanJob {
            id,
            data,
            status: "pending".into(),
            result: None,
            duration_ms: 0,
        });
        id
    }

    fn run(&self) {
        let jobs = Arc::clone(&self.jobs);
        let completed = Arc::clone(&self.completed);
        let mut handles = vec![];

        for _ in 0..self.max_workers {
            let jobs = Arc::clone(&jobs);
            let completed = Arc::clone(&completed);
            handles.push(thread::spawn(move || {
                loop {
                    let maybe_job = {
                        let mut jl = jobs.lock().unwrap();
                        let idx = jl.iter().position(|j| j.status == "pending");
                        match idx {
                            Some(i) => {
                                jl[i].status = "running".into();
                                Some((jl[i].data.clone(), jl[i].id))
                            }
                            None => None,
                        }
                    };

                    let (data, id) = match maybe_job {
                        Some(d) => d,
                        None => break,
                    };

                    let start = Instant::now();
                    let result = cryptotrace::analyzers::file::analyze_bytes(
                        &data, cryptotrace::types::SourceType::Binary,
                    );
                    let duration = start.elapsed();

                    let mut jl = jobs.lock().unwrap();
                    if let Some(ref mut j) = jl.iter_mut().find(|j| j.id == id) {
                        j.status = "done".into();
                        j.duration_ms = duration.as_millis() as u64;
                        j.result = match &result {
                            Ok(r) => Some(format!(
                                "algo={:?} type={} ent={:.2}",
                                r.algorithm, r.detected_type, r.entropy
                            )),
                            Err(e) => Some(format!("error={}", e)),
                        };
                    }
                    completed.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }

    fn summary(&self) {
        let jobs = self.jobs.lock().unwrap();
        let done = jobs.iter().filter(|j| j.status == "done").count();
        let total: u64 = jobs.iter().map(|j| j.duration_ms).sum();
        let avg = total as f64 / done.max(1) as f64;

        println!("\n=== Distributed Scan Summary ===");
        println!("  Total jobs: {}", jobs.len());
        println!("  Workers:    {}", self.max_workers);
        println!("  Avg/job:    {:.1}ms", avg);

        for job in jobs.iter() {
            println!("    Job {:3}: {:8}ms | {:?}", job.id, job.duration_ms,
                job.result.as_deref().unwrap_or("N/A"));
        }
    }
}

fn main() {
    println!("=== Distributed Scan Coordinator ===\n");

    let coordinator = Coordinator::new(4);

    let test_inputs: Vec<&[u8]> = vec![
        b"5d41402abc4b2a76b9719d911017c592",
        b"SGVsbG8gV29ybGQ=",
        b"d41d8cd98f00b204e9800998ecf8427e",
        b"e99a18c428cb38d5f260853678922e03",
        b"7c6a61b68d3d5b7c6a61b68d3d5b7c6a",
        b"password123!@#$%",
        b"00000000000000000000000000000000",
        b"ecWUoO0a0Yb1zB2xR3vA4sD5fG6hJ7kL8zX9cV0bN",
        b"abcdefghijklmnopqrstuvwxyz1234567890",
        b"cGFzc3dvcmQxMjM0NTY3ODk=",
    ];

    for data in &test_inputs {
        coordinator.submit(data.to_vec());
    }

    println!("Submitted {} jobs to {} workers\n", test_inputs.len(), coordinator.max_workers);

    let start = Instant::now();
    coordinator.run();
    let elapsed = start.elapsed();

    println!("\nAll workers finished in {:.2}s", elapsed.as_secs_f64());
    coordinator.summary();
}
