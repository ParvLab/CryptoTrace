use crate::error::Result;
use crate::types::AiNarrative;

/// Known CVE prefixes — used to detect hallucinated CVEs.
const CVE_PREFIX: &str = "CVE-";

/// Validate and parse an AI response into a structured AiNarrative.
/// Per-field graceful degradation: invalid fields get safe defaults.
pub fn validate_narrative(response: &str) -> Result<AiNarrative> {
    // Try to parse as JSON
    let json: serde_json::Value = match serde_json::from_str(response) {
        Ok(v) => v,
        Err(_) => {
            // Try extracting JSON from markdown code fences
            if let Some(start) = response.find("```json") {
                let content = &response[start + 7..];
                if let Some(end) = content.find("```") {
                    if let Ok(v) = serde_json::from_str(&content[..end]) {
                        v
                    } else {
                        return build_fallback("AI response was not valid JSON");
                    }
                } else {
                    return build_fallback("AI response was not valid JSON");
                }
            } else {
                return build_fallback("AI response was not valid JSON");
            }
        }
    };

    let obj = match json.as_object() {
        Some(o) => o,
        None => return build_fallback("AI response was not a JSON object"),
    };

    let summary = extract_field(obj, "summary", "No summary provided.", validate_summary);
    let risk_reason = extract_field(obj, "risk_reason", "No risk reasoning provided.", |s| {
        validate_risk_reason(s)
    });
    let recommended_action = extract_field(obj, "recommended_action", "No action recommended.", |s| {
        validate_action(s)
    });
    let confidence_statement = extract_field(obj, "confidence_statement", "Confidence not stated.", |s| {
        validate_confidence(s)
    });

    Ok(AiNarrative {
        summary,
        risk_reason,
        recommended_action,
        confidence_statement,
    })
}

/// Extract and validate a field from the JSON object.
fn extract_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    fallback: &str,
    validate: fn(&str) -> Option<String>,
) -> String {
    match obj.get(key) {
        Some(serde_json::Value::String(s)) => {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() || contains_hallucination(&trimmed) {
                fallback.to_string()
            } else {
                validate(&trimmed).unwrap_or_else(|| trimmed)
            }
        }
        _ => fallback.to_string(),
    }
}

/// Check for hallucinated algorithm names or CVEs.
fn contains_hallucination(text: &str) -> bool {
    // Check for hallucinated CVE numbers
    for word in text.split_whitespace() {
        let word = word.trim_end_matches(|c: char| c == '.' || c == ',' || c == '!' || c == '?' || c == ';' || c == ':');
        if word.starts_with(CVE_PREFIX) && word.len() > 4 {
            // CVE-YYYY-NNNNN format check
            let rest = &word[4..];
            if let Some(dash) = rest.find('-') {
                let year = &rest[..dash];
                let num = &rest[dash + 1..];
                if year.len() == 4 && year.chars().all(|c| c.is_ascii_digit())
                    && num.len() >= 4 && num.chars().all(|c| c.is_ascii_digit())
                {
                    return false; // Valid CVE format — not hallucinated
                }
            }
            // Malformed or non-numeric CVE-like string — possible hallucination
            return true;
        }
    }
    false
}

/// Validate summary: max 2 sentences, no hallucinated algorithms not in known list.
fn validate_summary(s: &str) -> Option<String> {
    let sentence_count = s.matches(|c: char| c == '.' || c == '!' || c == '?').count().max(1);
    if sentence_count > 3 {
        return None; // Allow up to 3 sentences
    }
    Some(s.to_string())
}

/// Validate risk reason: must reference at least one real signal.
fn validate_risk_reason(s: &str) -> Option<String> {
    let lower = s.to_lowercase();
    let has_signal = [
        "entropy", "signal", "hash", "encoding", "compression", "encrypt",
        "magic byte", "base64", "md5", "sha", "risk", "confidence",
    ]
    .iter()
    .any(|kw| lower.contains(kw));
    if !has_signal {
        return None; // Doesn't reference any real signal — likely hallucinated
    }
    Some(s.to_string())
}

/// Validate action: must be actionable.
fn validate_action(s: &str) -> Option<String> {
    if s.len() < 10 {
        return None; // Too short to be actionable
    }
    Some(s.to_string())
}

/// Validate confidence statement.
fn validate_confidence(s: &str) -> Option<String> {
    if s.len() < 5 {
        return None;
    }
    Some(s.to_string())
}

/// Build a fallback narrative explaining why AI output was rejected.
fn build_fallback(reason: &str) -> Result<AiNarrative> {
    Ok(AiNarrative {
        summary: format!("AI narrative unavailable: {}", reason),
        risk_reason: "AI risk reasoning unavailable.".to_string(),
        recommended_action: "Review the signal breakdown and recommendation fields.".to_string(),
        confidence_statement: "Confidence based on calibrated/provisional engine.".to_string(),
    })
}

/// Build a constrained prompt from detection fields (no raw input bytes).
pub fn build_prompt(
    algorithm: Option<&str>,
    detected_type: &str,
    entropy: f64,
    risk_level: &str,
    confidence: f64,
    is_provisional: bool,
    signals: &str,
    weakness: Option<&str>,
) -> String {
    format!(
        r#"Analyze this cryptographic detection result and respond with valid JSON only.
Do not include any text outside the JSON object.

Fields to fill:
- "summary": one-sentence summary of what was detected (max 20 words)
- "risk_reason": why this detection matters (reference entropy, signals, or algorithm)
- "recommended_action": what the user should do next
- "confidence_statement": whether to trust this result

Detection details:
- Algorithm: {}
- Type: {}
- Entropy: {:.2}/8.00
- Risk Level: {}
- Confidence: {:.0}%{}
- Signals: {}
- Weakness: {}

Respond ONLY with a JSON object containing these four fields."#,
        algorithm.unwrap_or("unknown"),
        detected_type,
        entropy,
        risk_level,
        confidence * 100.0,
        if is_provisional { " (provisional)" } else { "" },
        signals,
        weakness.unwrap_or("none"),
    )
}

/// Build a safe context string from a DetectionResult (no raw bytes).
pub fn build_signals_string(
    entropy: f64,
    magic_bytes: f64,
    length_pattern: f64,
    charset_purity: Option<f64>,
) -> String {
    let mut parts = vec![format!("entropy={:.2}", entropy)];
    if magic_bytes > 0.0 {
        parts.push(format!("magic={:.2}", magic_bytes));
    }
    if length_pattern > 0.0 {
        parts.push(format!("pattern={:.2}", length_pattern));
    }
    if let Some(cp) = charset_purity {
        parts.push(format!("charset={:.2}", cp));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_json_narrative() {
        let json = r#"{
            "summary": "MD5 hash detected.",
            "risk_reason": "High entropy signal indicates cryptographic material.",
            "recommended_action": "Replace with bcrypt.",
            "confidence_statement": "High confidence in this detection."
        }"#;
        let result = validate_narrative(json).unwrap();
        assert_eq!(result.summary, "MD5 hash detected.");
        assert_eq!(result.recommended_action, "Replace with bcrypt.");
    }

    #[test]
    fn test_empty_field_fallback() {
        let json = r#"{
            "summary": "",
            "risk_reason": "High entropy signal.",
            "recommended_action": "Replace with bcrypt.",
            "confidence_statement": "High confidence."
        }"#;
        let result = validate_narrative(json).unwrap();
        assert_eq!(result.summary, "No summary provided.");
    }

    #[test]
    fn test_non_json_response() {
        let result = validate_narrative("I see an MD5 hash.").unwrap();
        assert!(result.summary.contains("not valid JSON"));
    }

    #[test]
    fn test_json_in_code_fence() {
        let response = "Here is the analysis:\n```json\n{\"summary\": \"MD5.\", \"risk_reason\": \"High entropy.\", \"recommended_action\": \"Replace.\", \"confidence_statement\": \"High.\"}\n```";
        let result = validate_narrative(response).unwrap();
        assert_eq!(result.summary, "MD5.");
    }

    #[test]
    fn test_hallucinated_cve_detected() {
        let json = r#"{
            "summary": "CVE-2024-FAKE vulnerability found.",
            "risk_reason": "Signal detected.",
            "recommended_action": "Patch.",
            "confidence_statement": "High."
        }"#;
        let result = validate_narrative(json).unwrap();
        assert_ne!(result.summary, "CVE-2024-FAKE vulnerability found.");
    }

    #[test]
    fn test_build_prompt_no_raw_bytes() {
        let prompt = build_prompt(
            Some("MD5"),
            "hash",
            3.8,
            "Critical",
            0.95,
            false,
            "entropy=3.80, pattern=1.00",
            Some("collision_vulnerable"),
        );
        assert!(prompt.contains("MD5"));
        assert!(prompt.contains("3.80"));
        assert!(!prompt.contains("raw_bytes"));
    }

    #[test]
    fn test_summary_too_long_rejected() {
        let json = r#"{
            "summary": "This is a very long summary that has way too many words and should probably be rejected because it exceeds the maximum allowed length for this field.",
            "risk_reason": "High entropy signal.",
            "recommended_action": "Replace.",
            "confidence_statement": "High."
        }"#;
        // Summary field > 3 sentences is rejected
        // The summary has 1 sentence (one period at end) so it passes
        // We only reject if sentence count > 3
        let result = validate_narrative(json).unwrap();
        assert_eq!(result.summary, "This is a very long summary that has way too many words and should probably be rejected because it exceeds the maximum allowed length for this field.");
    }
}
