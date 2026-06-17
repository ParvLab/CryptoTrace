use std::fmt::Write;

use crate::types::DetectionResult;

/// Format a DetectionResult as a standalone HTML report page.
pub fn format_html(result: &DetectionResult) -> String {
    let mut html = String::new();

    html.push_str(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>"#);
    html.push_str("CryptoTrace Analysis Report");
    html.push_str(r#"</title><style>"#);
    html.push_str(CSS);
    html.push_str(r#"</style></head><body>"#);

    html.push_str(r#"<div class="container">"#);
    html.push_str(r#"<div class="header"><h1>CryptoTrace Analysis Report</h1>"#);
    html.push_str(&format!(
        "<span class=\"version\">v{}</span></div>",
        result.engine_version
    ));

    // Summary
    html.push_str(r#"<div class="card"><h2>Summary</h2><table>"#);
    html.push_str(&format!(
        "<tr><td>Input Hash</td><td class=\"mono\">{}</td></tr>",
        result.input_hash
    ));
    html.push_str(&format!(
        "<tr><td>Source</td><td>{:?}</td></tr>",
        result.source_type
    ));
    html.push_str(&format!(
        "<tr><td>Entropy</td><td>{:.2} / 8.00</td></tr>",
        result.entropy
    ));
    html.push_str(&format!(
        "<tr><td>Risk Level</td><td class=\"risk-{}\">{:?}</td></tr>",
        result.risk_level.to_string().to_lowercase(),
        result.risk_level
    ));
    html.push_str("</table></div>");

    // Detection
    html.push_str(r#"<div class="card"><h2>Detection</h2><table>"#);
    html.push_str(&format!(
        "<tr><td>Type</td><td>{}</td></tr>",
        result.detected_type
    ));
    html.push_str(&format!(
        "<tr><td>Algorithm</td><td>{}</td></tr>",
        result.algorithm.as_deref().unwrap_or("Unknown")
    ));
    html.push_str(&format!(
        "<tr><td>Confidence</td><td>{:.1}% {}</td></tr>",
        result.confidence * 100.0,
        if result.calibrated {
            "(calibrated)"
        } else {
            "(provisional)"
        }
    ));
    if let Some(ref weakness) = result.weakness {
        html.push_str(&format!("<tr><td>Weakness</td><td>{}</td></tr>", weakness));
    }
    if !result.weakness_cve.is_empty() {
        html.push_str(&format!(
            "<tr><td>CVEs</td><td>{}</td></tr>",
            result.weakness_cve.join(", ")
        ));
    }
    if !result.recommendations.is_empty() {
        html.push_str(&format!(
            "<tr><td>Recommendation</td><td>{}</td></tr>",
            result.recommendations.join("; ")
        ));
    }
    html.push_str("</table></div>");

    // Signals
    if let Some(ref sig) = result.signals {
        html.push_str(r#"<div class="card"><h2>Signal Breakdown</h2><table>"#);
        html.push_str(&format!(
            "<tr><td>Entropy</td><td>{:.2}</td></tr>",
            sig.entropy
        ));
        if let Some(bd) = sig.byte_distribution {
            html.push_str(&format!(
                "<tr><td>Byte Distribution</td><td>{:.2}</td></tr>",
                bd
            ));
        }
        html.push_str(&format!(
            "<tr><td>Block Alignment</td><td>{:.2}</td></tr>",
            sig.block_alignment
        ));
        html.push_str(&format!(
            "<tr><td>Magic Bytes</td><td>{:.2}</td></tr>",
            sig.magic_bytes
        ));
        html.push_str(&format!(
            "<tr><td>Length Pattern</td><td>{:.2}</td></tr>",
            sig.length_pattern
        ));
        if let Some(cp) = sig.charset_purity {
            html.push_str(&format!(
                "<tr><td>Charset Purity</td><td>{:.2}</td></tr>",
                cp
            ));
        }
        if let Some(wv) = sig.window_variance {
            html.push_str(&format!(
                "<tr><td>Window Variance</td><td>{:.2}</td></tr>",
                wv
            ));
        }
        html.push_str("</table></div>");
    }

    // Primary drivers & conflicts
    if !result.primary_drivers.is_empty() {
        html.push_str(r#"<div class="card"><h2>Primary Drivers</h2><ul>"#);
        for d in &result.primary_drivers {
            html.push_str(&format!("<li>{}</li>", d));
        }
        html.push_str("</ul></div>");
    }
    if !result.conflicting_signals.is_empty() {
        html.push_str(r#"<div class="card"><h2>Conflicting Signals</h2><ul>"#);
        for c in &result.conflicting_signals {
            html.push_str(&format!("<li>{}</li>", c));
        }
        html.push_str("</ul></div>");
    }

    // Decision trace
    if let Some(ref trace) = result.decision_trace {
        html.push_str(&format!(
            r#"<div class="card"><h2>Decision Trace</h2><p>{}</p></div>"#,
            trace
        ));
    }

    // Layer tree
    if !result.layers.is_empty() {
        html.push_str(r#"<div class="card"><h2>Layer Tree</h2><ul>"#);
        for layer in &result.layers {
            write!(
                html,
                "<li>[{}] {} ({:.0}% confidence)</li>",
                layer.algorithm.as_deref().unwrap_or("?"),
                layer.detected_type,
                layer.confidence * 100.0
            )
            .ok();
        }
        html.push_str("</ul></div>");
    }

    // AI narrative
    if let Some(ref ai) = result.ai_narrative {
        html.push_str(r#"<div class="card"><h2>AI Narrative</h2>"#);
        html.push_str(&format!("<p><strong>Summary:</strong> {}</p>", ai.summary));
        html.push_str(&format!("<p><strong>Risk:</strong> {}</p>", ai.risk_reason));
        html.push_str(&format!(
            "<p><strong>Action:</strong> {}</p>",
            ai.recommended_action
        ));
        html.push_str("</div>");
    }

    html.push_str("</div></body></html>");
    html
}

const CSS: &str = r#"
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
.container { max-width: 800px; margin: 0 auto; }
.header { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; }
.header h1 { margin: 0; font-size: 1.5em; color: #58a6ff; }
.version { color: #8b949e; font-size: 0.9em; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
        padding: 16px; margin-bottom: 16px; }
.card h2 { margin: 0 0 12px 0; font-size: 1.1em; color: #f0f6fc; }
table { width: 100%; border-collapse: collapse; }
td { padding: 6px 8px; border-bottom: 1px solid #21262d; }
td:first-child { color: #8b949e; width: 160px; }
.mono { font-family: 'SFMono-Regular', Consolas, monospace; }
ul { margin: 0; padding-left: 20px; }
li { margin: 4px 0; }
p { margin: 8px 0; line-height: 1.5; }
.risk-critical { color: #f85149; font-weight: bold; }
.risk-high { color: #d29922; font-weight: bold; }
.risk-medium { color: #db6d28; }
.risk-low { color: #3fb950; }
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AiNarrative, RiskLevel, SignalBreakdown, SourceType};

    #[test]
    fn test_format_html_basic() {
        let result = DetectionResult {
            input_hash: "abc123".to_string(),
            source_type: SourceType::String,
            entropy: 3.8,
            sliding_entropy: None,
            detected_type: "hash".to_string(),
            algorithm: Some("MD5".to_string()),
            confidence: 0.98,
            calibrated: true,
            calibration_samples: Some(500),
            heuristic_raw: Some(0.95),
            confidence_is_provisional: false,
            false_positive_risk: 0.01,
            risk_level: RiskLevel::Critical,
            weakness: Some("collision_vulnerable".to_string()),
            weakness_cve: vec!["CVE-2013-4103".to_string()],
            recommendations: vec!["Use bcrypt".to_string()],
            signals: Some(SignalBreakdown {
                entropy: 0.9,
                byte_distribution: Some(0.8),
                block_alignment: 0.0,
                magic_bytes: 0.0,
                length_pattern: 1.0,
                charset_purity: Some(1.0),
                window_variance: Some(0.1),
            }),
            primary_drivers: vec!["length_pattern".to_string()],
            conflicting_signals: vec!["magic_bytes".to_string()],
            decision_trace: Some("Length pattern was the primary driver".to_string()),
            layers: vec![],
            ai_narrative: Some(AiNarrative {
                summary: "Test summary".to_string(),
                risk_reason: "MD5 is collision vulnerable".to_string(),
                recommended_action: "Migrate to SHA256".to_string(),
                confidence_statement: "Confidence is 98%".to_string(),
            }),
            detection_context: crate::types::DetectionContext::Forensics,
            engine_version: "0.1.0".to_string(),
            signature_db_version: "1.0.0".to_string(),
        };

        let html = format_html(&result);
        assert!(html.contains("MD5"));
        assert!(html.contains("collision_vulnerable"));
        assert!(html.contains("CVE-2013-4103"));
        assert!(html.contains("Test summary"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn test_format_html_empty() {
        let result = DetectionResult::default();
        let html = format_html(&result);
        assert!(html.contains("CryptoTrace Analysis Report"));
        assert!(html.contains("</html>"));
    }
}
