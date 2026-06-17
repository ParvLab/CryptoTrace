use crate::types::DetectionResult;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Directory for audit log output (configurable via CRYPTOTRACE_AUDIT_DIR).
fn audit_dir() -> PathBuf {
    std::env::var("CRYPTOTRACE_AUDIT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
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
            base.join("cryptotrace").join("audit")
        })
}

/// JSON-lines audit log file handle, lazily initialized and guarded by a mutex.
static AUDIT_FILE: std::sync::LazyLock<Mutex<Option<std::fs::File>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

fn ensure_audit_file() -> Option<std::fs::File> {
    let mut guard = AUDIT_FILE.lock().ok()?;
    if guard.is_some() {
        return guard.as_ref().map(|f| f.try_clone().ok()).flatten();
    }
    let dir = audit_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("audit.jsonl");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()?;
    *guard = Some(file.try_clone().ok()?);
    Some(file)
}

/// Log analysis events for audit trail as structured JSON-lines.
/// Writes to ~/.cryptotrace/audit/audit.jsonl (or CRYPTOTRACE_AUDIT_DIR).
pub fn log_analysis(result: &DetectionResult) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let entry = serde_json::json!({
        "event": "analysis_complete",
        "timestamp": timestamp,
        "input_hash": result.input_hash,
        "detected_type": result.detected_type,
        "algorithm": result.algorithm,
        "confidence": result.confidence,
        "risk_level": format!("{}", result.risk_level),
        "false_positive_risk": result.false_positive_risk,
        "calibrated": result.calibrated,
        "weakness": result.weakness,
        "cve_ids": result.weakness_cve,
        "detection_context": format!("{:?}", result.detection_context),
        "engine_version": result.engine_version,
        "signature_db_version": result.signature_db_version,
        "source_type": format!("{:?}", result.source_type),
    });

    // Write JSON-lines to file (best-effort)
    if let Some(mut file) = ensure_audit_file() {
        use std::io::Write;
        let _ = writeln!(&mut file, "{}", entry);
    }

    tracing::info!(
        input_hash = %result.input_hash,
        detected_type = %result.detected_type,
        algorithm = ?result.algorithm,
        confidence = result.confidence,
        risk_level = ?result.risk_level,
        timestamp = timestamp,
        "Analysis complete"
    );
}
