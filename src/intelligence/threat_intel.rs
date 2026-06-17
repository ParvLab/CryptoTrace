use crate::error::{CryptoTraceError, Result};
use std::collections::HashMap;

/// Configuration for threat intelligence providers.
#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    pub vt_api_key: Option<String>,
    pub yara_rules_path: Option<String>,
    pub enable_scan: bool,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            vt_api_key: None,
            yara_rules_path: None,
            enable_scan: false,
        }
    }
}

/// A threat intelligence report for a given hash or file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatReport {
    pub input_hash: String,
    pub positives: u32,
    pub total_scanners: u32,
    pub malicious: bool,
    pub source: String,
    pub scan_date: Option<String>,
    pub threat_labels: Vec<String>,
    pub vt_link: Option<String>,
}

/// YARA match result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub offset: usize,
}

/// Query VirusTotal for a file hash.
pub async fn query_virustotal(hash: &str, api_key: &str) -> Result<ThreatReport> {
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| CryptoTraceError::Other(format!("HTTP client error: {}", e)))?;

    let resp = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await
        .map_err(|e| CryptoTraceError::Other(format!("VirusTotal request failed: {}", e)))?;

    if !resp.status().is_success() {
        return Err(CryptoTraceError::Other(format!(
            "VirusTotal returned HTTP {}",
            resp.status()
        )));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| CryptoTraceError::Other(format!("VirusTotal parse error: {}", e)))?;

    let attributes = &json["data"]["attributes"];
    let stats = &attributes["last_analysis_stats"];
    let positives = stats["malicious"].as_u64().unwrap_or(0) as u32;
    let total = stats["undetected"].as_u64().unwrap_or(0)
        + stats["harmless"].as_u64().unwrap_or(0)
        + stats["malicious"].as_u64().unwrap_or(0)
        + stats["suspicious"].as_u64().unwrap_or(0)
        + stats["timeout"].as_u64().unwrap_or(0);

    let mut labels: Vec<String> = vec![];
    if let Some(categories) = attributes["categories"].as_object() {
        for (engine, category) in categories {
            if let Some(cat) = category.as_str() {
                if cat != "harmless" && cat != "undetected" {
                    labels.push(format!("{}: {}", engine, cat));
                }
            }
        }
    }

    Ok(ThreatReport {
        input_hash: hash.to_string(),
        positives,
        total_scanners: total as u32,
        malicious: positives > 0,
        source: "VirusTotal".to_string(),
        scan_date: attributes["last_analysis_date"]
            .as_i64()
            .map(|ts| unix_to_iso(ts)),
        threat_labels: {
            if labels.len() > 10 {
                labels.truncate(10);
            }
            labels
        },
        vt_link: Some(format!("https://www.virustotal.com/gui/file/{}", hash)),
    })
}

/// Scan a byte buffer with YARA rules.
pub fn scan_yara(data: &[u8], rules_path: &str) -> Result<Vec<YaraMatch>> {
    // Attempt to use the `yara` crate via dynamic loading or shell out to `yara` CLI.
    // This implementation shells out to the `yara` command-line tool.
    let temp_dir = std::env::temp_dir();
    let data_file = temp_dir.join("cryptotrace_yara_scan.bin");
    std::fs::write(&data_file, data)
        .map_err(|e| CryptoTraceError::Other(format!("Cannot write temp scan file: {}", e)))?;

    let output = std::process::Command::new("yara")
        .arg("-s") // print matching strings
        .arg("-w") // disable warnings
        .arg(rules_path)
        .arg(&data_file)
        .output();

    // Clean up temp file
    let _ = std::fs::remove_file(&data_file);

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.is_empty() {
                return Ok(vec![]);
            }

            let mut matches: Vec<YaraMatch> = vec![];
            for line in stdout.lines() {
                // YARA output format: "rule_name namespace" or "rule_name"
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.is_empty() {
                    continue;
                }
                let rule_name = parts[0].to_string();
                let namespace = parts.get(1).unwrap_or(&"").to_string();

                matches.push(YaraMatch {
                    rule: rule_name,
                    namespace,
                    tags: vec![],
                    meta: HashMap::new(),
                    offset: 0,
                });
            }
            Ok(matches)
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Err(CryptoTraceError::Other(
                    "YARA CLI not found. Install yara from https://virustotal.github.io/yara/"
                        .to_string(),
                ));
            }
            Err(CryptoTraceError::Other(format!(
                "YARA execution error: {}",
                e
            )))
        }
    }
}

/// Perform composite threat intelligence scan: VirusTotal + YARA.
pub async fn composite_threat_scan(
    hash: &str,
    data: &[u8],
    config: &ThreatIntelConfig,
) -> Result<Vec<ThreatReport>> {
    let mut reports: Vec<ThreatReport> = vec![];

    // VirusTotal query
    if let Some(ref api_key) = config.vt_api_key {
        match query_virustotal(hash, api_key).await {
            Ok(report) => reports.push(report),
            Err(e) => tracing::warn!("VirusTotal query failed: {}", e),
        }
    }

    // YARA scan
    if let Some(ref rules_path) = config.yara_rules_path {
        match scan_yara(data, rules_path) {
            Ok(matches) => {
                if !matches.is_empty() {
                    let labels: Vec<String> = matches.iter().map(|m| m.rule.clone()).collect();
                    reports.push(ThreatReport {
                        input_hash: hash.to_string(),
                        positives: matches.len() as u32,
                        total_scanners: matches.len() as u32,
                        malicious: true,
                        source: "YARA".to_string(),
                        scan_date: None,
                        threat_labels: labels,
                        vt_link: None,
                    });
                }
            }
            Err(e) => tracing::warn!("YARA scan failed: {}", e),
        }
    }

    Ok(reports)
}

fn unix_to_iso(ts: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = if ts > 0 { ts as u64 } else { 0 };
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(secs))
        .and_then(|t| {
            t.duration_since(UNIX_EPOCH).ok().map(|d| {
                let s = d.as_secs();
                let millis = d.subsec_millis();
                format!("{}.{:03}", s, millis)
            })
        })
        .unwrap_or_else(|| "0.000".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_not_found_graceful() {
        let result = scan_yara(b"test data", "/nonexistent/rules.yara");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found") || err.contains("error"));
    }

    #[test]
    fn test_threat_report_serialization() {
        let report = ThreatReport {
            input_hash: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            positives: 3,
            total_scanners: 62,
            malicious: true,
            source: "VirusTotal".to_string(),
            scan_date: Some("1716000000.000".to_string()),
            threat_labels: vec!["Trojan.Generic.123".to_string()],
            vt_link: Some(
                "https://www.virustotal.com/gui/file/d41d8cd98f00b204e9800998ecf8427e".to_string(),
            ),
        };

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("positives"));
        assert!(json.contains("malicious"));
    }

    #[tokio::test]
    async fn test_composite_scan_no_api_key() {
        let config = ThreatIntelConfig::default();
        let reports = composite_threat_scan("e99a18c428cb38d5f260853678922e03", b"test", &config)
            .await
            .unwrap();
        assert!(reports.is_empty());
    }
}
