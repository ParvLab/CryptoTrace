/// SIEM integration: CEF and LEEF log formatters for SOC ingestion.
///
/// # CEF Format (ArcSight Common Event Format)
/// `CEF:0|Vendor|Product|Version|EventID|Name|Severity|Extension`
///
/// # LEEF Format (IBM QRadar Log Event Extended Format)
/// `LEEF:2.0|Vendor|Product|Version|EventID|Extension`
///
/// # Syslog Transport
/// Supports both UDP and TCP syslog via environment configuration:
/// - `SIEM_SYSLOG_ADDR` — host:port (e.g. `192.168.1.100:514`)
/// - `SIEM_SYSLOG_PROTO` — `udp` (default) or `tcp`
/// - `SIEM_SYSLOG_FORMAT` — `cef` (default) or `leef`
use crate::types::DetectionResult;

/// Format a `DetectionResult` as a CEF log line.
pub fn format_cef(result: &DetectionResult) -> String {
    let vendor = "CryptoTrace";
    let product = "CryptoTrace";
    let version = &result.engine_version;
    let event_id = "100";
    let name = match result.risk_level {
        crate::types::RiskLevel::Critical => "Critical Detection Alert",
        crate::types::RiskLevel::High => "High Detection Alert",
        crate::types::RiskLevel::Medium => "Medium Detection Alert",
        crate::types::RiskLevel::Low => "Low Detection Alert",
        crate::types::RiskLevel::Unknown => "Detection Alert",
    };
    let severity = cef_severity(result.risk_level);

    let mut ext = String::new();
    ext.push_str(&format!("inputHash={} ", result.input_hash));
    ext.push_str(&format!(
        "detectedType={} ",
        escape_cef(&result.detected_type)
    ));
    if let Some(ref algo) = result.algorithm {
        ext.push_str(&format!("algorithm={} ", escape_cef(algo)));
    }
    ext.push_str(&format!("confidence={:.2} ", result.confidence));
    ext.push_str(&format!("riskLevel={} ", result.risk_level));
    ext.push_str(&format!("entropy={:.2} ", result.entropy));
    ext.push_str(&format!(
        "falsePositiveRisk={:.4} ",
        result.false_positive_risk
    ));
    if let Some(ref weakness) = result.weakness {
        ext.push_str(&format!("weakness={} ", escape_cef(weakness)));
    }
    if !result.weakness_cve.is_empty() {
        ext.push_str(&format!("cveIds={} ", result.weakness_cve.join(",")));
    }
    ext.push_str(&format!("context={:?} ", result.detection_context));
    ext.push_str(&format!("calibrated={} ", result.calibrated));
    ext.push_str(&format!(
        "primaryDrivers={} ",
        result.primary_drivers.join(",")
    ));

    format!(
        "CEF:0|{}|{}|{}|{}|{}|{}|{}",
        vendor,
        product,
        version,
        event_id,
        name,
        severity,
        ext.trim()
    )
}

/// Format a `DetectionResult` as a LEEF log line.
pub fn format_leef(result: &DetectionResult) -> String {
    let vendor = "CryptoTrace";
    let product = "CryptoTrace";
    let version = &result.engine_version;
    let event_id = "100";

    let mut ext = String::new();
    ext.push_str(&format!(
        "cat={} ",
        escape_leef_value(&result.detected_type)
    ));
    ext.push_str(&format!("sev={} ", leef_severity(result.risk_level)));
    ext.push_str(&format!("inputHash={} ", &result.input_hash));
    if let Some(ref algo) = result.algorithm {
        ext.push_str(&format!("algorithm={} ", escape_leef_value(algo)));
    }
    ext.push_str(&format!("confidence={:.2} ", result.confidence));
    ext.push_str(&format!("riskLevel={} ", result.risk_level));
    ext.push_str(&format!("entropy={:.2} ", result.entropy));
    ext.push_str(&format!("fpr={:.4} ", result.false_positive_risk));
    ext.push_str(&format!("context={:?} ", result.detection_context));
    ext.push_str(&format!("calibrated={} ", result.calibrated));
    ext.push_str(&format!(
        "primaryDrivers={} ",
        result.primary_drivers.join(",")
    ));

    format!(
        "LEEF:2.0|{}|{}|{}|{}|{}",
        vendor,
        product,
        version,
        event_id,
        ext.trim()
    )
}

/// CEF severity: 0-10 scale, 10=most severe.
fn cef_severity(level: crate::types::RiskLevel) -> i32 {
    match level {
        crate::types::RiskLevel::Critical => 10,
        crate::types::RiskLevel::High => 8,
        crate::types::RiskLevel::Medium => 5,
        crate::types::RiskLevel::Low => 2,
        crate::types::RiskLevel::Unknown => 3,
    }
}

/// LEEF severity: 0-10 scale, 10=most severe (same mapping).
fn leef_severity(level: crate::types::RiskLevel) -> i32 {
    cef_severity(level)
}

/// Escape special chars in CEF extension values: `=` and `\` and `|` → URL-encoded.
fn escape_cef(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '|' => out.push_str("\\|"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
    out
}

/// Escape special chars in LEEF extension values: `|` and `\` and `=` and `\n`.
fn escape_leef_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
    out
}

/// Syslog transport configuration.
pub struct SyslogConfig {
    pub addr: String,
    pub protocol: SyslogProtocol,
    pub format: SyslogFormat,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            addr: std::env::var("SIEM_SYSLOG_ADDR").unwrap_or_else(|_| "127.0.0.1:514".to_string()),
            protocol: match std::env::var("SIEM_SYSLOG_PROTO").as_deref() {
                Ok("tcp") => SyslogProtocol::Tcp,
                _ => SyslogProtocol::Udp,
            },
            format: match std::env::var("SIEM_SYSLOG_FORMAT").as_deref() {
                Ok("leef") => SyslogFormat::Leef,
                _ => SyslogFormat::Cef,
            },
        }
    }
}

pub enum SyslogProtocol {
    Udp,
    Tcp,
}

pub enum SyslogFormat {
    Cef,
    Leef,
}

/// Send a DetectionResult to a syslog server.
pub async fn send_to_syslog(result: &DetectionResult) -> Result<(), String> {
    let config = SyslogConfig::default();
    send_to_syslog_with_config(result, &config).await
}

/// Send a DetectionResult to a syslog server with explicit configuration.
pub async fn send_to_syslog_with_config(
    result: &DetectionResult,
    config: &SyslogConfig,
) -> Result<(), String> {
    let message = match config.format {
        SyslogFormat::Cef => format_cef(result),
        SyslogFormat::Leef => format_leef(result),
    };

    match config.protocol {
        SyslogProtocol::Udp => send_udp(&config.addr, &message).await,
        SyslogProtocol::Tcp => send_tcp(&config.addr, &message).await,
    }
}

async fn send_udp(addr: &str, message: &str) -> Result<(), String> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;
    socket
        .send_to(message.as_bytes(), addr)
        .await
        .map_err(|e| format!("Failed to send UDP syslog: {}", e))?;
    Ok(())
}

async fn send_tcp(addr: &str, message: &str) -> Result<(), String> {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("Failed to connect TCP syslog: {}", e))?;
    use tokio::io::AsyncWriteExt;
    stream
        .write_all(message.as_bytes())
        .await
        .map_err(|e| format!("Failed to send TCP syslog: {}", e))?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|e| format!("Failed to write TCP syslog newline: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DetectionContext, DetectionResult, RiskLevel};

    fn sample_result() -> DetectionResult {
        DetectionResult {
            input_hash: "abc123".into(),
            detected_type: "hash".into(),
            algorithm: Some("MD5".into()),
            confidence: 0.98,
            risk_level: RiskLevel::Critical,
            entropy: 3.8,
            false_positive_risk: 0.021,
            weakness: Some("collision_vulnerable".into()),
            weakness_cve: vec!["CVE-2013-6623".into()],
            detection_context: DetectionContext::Forensics,
            calibrated: true,
            engine_version: "0.2.0".into(),
            signature_db_version: "1.0.0".into(),
            primary_drivers: vec!["entropy".into(), "length_pattern".into()],
            ..Default::default()
        }
    }

    #[test]
    fn test_cef_format() {
        let result = sample_result();
        let cef = format_cef(&result);
        assert!(cef.starts_with("CEF:0|"), "starts with CEF: {}", cef);
        assert!(
            cef.contains("inputHash=abc123"),
            "contains inputHash: {}",
            cef
        );
        assert!(cef.contains("algorithm=MD5"), "contains algorithm: {}", cef);
        assert!(
            cef.contains("riskLevel=critical"),
            "contains riskLevel: {}",
            cef
        );
        assert!(
            cef.contains("confidence=0.98"),
            "contains confidence: {}",
            cef
        );
    }

    #[test]
    fn test_leef_format() {
        let result = sample_result();
        let leef = format_leef(&result);
        assert!(leef.starts_with("LEEF:2.0|"), "starts with LEEF: {}", leef);
        assert!(
            leef.contains("inputHash=abc123"),
            "contains inputHash: {}",
            leef
        );
        assert!(
            leef.contains("algorithm=MD5"),
            "contains algorithm: {}",
            leef
        );
        assert!(
            leef.contains("riskLevel=critical"),
            "contains riskLevel: {}",
            leef
        );
        assert!(
            leef.contains("confidence=0.98"),
            "contains confidence: {}",
            leef
        );
        assert!(leef.contains("sev=10"), "contains sev: {}", leef);
    }

    #[test]
    fn test_cef_escape_special_chars() {
        let s = "a=b|c\\d\ne";
        let escaped = escape_cef(s);
        assert!(
            escaped.contains("\\="),
            "should have escaped =: {}",
            escaped
        );
        assert!(
            escaped.contains("\\|"),
            "should have escaped |: {}",
            escaped
        );
        assert!(
            escaped.contains("\\\\"),
            "should have escaped \\: {}",
            escaped
        );
        assert!(
            escaped.contains("\\n"),
            "should have escaped newline: {}",
            escaped
        );
        // The original = and | and \ should still be present (as part of escape sequences)
        assert!(
            escaped.contains('='),
            "= should still appear as \\=: {}",
            escaped
        );
    }

    #[test]
    fn test_low_risk_cef_severity() {
        let result = DetectionResult {
            risk_level: RiskLevel::Low,
            input_hash: "x".into(),
            engine_version: "0.2.0".into(),
            signature_db_version: "1.0.0".into(),
            ..Default::default()
        };
        let cef = format_cef(&result);
        assert!(cef.contains("Low Detection Alert"));
    }

    #[test]
    fn test_empty_algorithm_omitted() {
        let result = DetectionResult {
            input_hash: "x".into(),
            engine_version: "0.2.0".into(),
            signature_db_version: "1.0.0".into(),
            ..Default::default()
        };
        let cef = format_cef(&result);
        assert!(!cef.contains("algorithm="));
    }
}
