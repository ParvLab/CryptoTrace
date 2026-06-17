use cryptotrace::types::RiskLevel;

fn main() {
    let result = cryptotrace::types::DetectionResult {
        input_hash: "abc123".into(),
        source_type: cryptotrace::types::SourceType::Binary,
        entropy: 7.8,
        sliding_entropy: None,
        detected_type: "Base64".into(),
        algorithm: Some("SHA256".into()),
        confidence: 0.94,
        calibrated: true,
        calibration_samples: Some(500),
        heuristic_raw: Some(0.89),
        confidence_is_provisional: false,
        false_positive_risk: 0.02,
        risk_level: RiskLevel::Medium,
        weakness: Some("Known hash weakness".into()),
        weakness_cve: vec!["CVE-2023-1234".into()],
        recommendations: Vec::new(),
        signals: None,
        primary_drivers: Vec::new(),
        conflicting_signals: Vec::new(),
        decision_trace: None,
        layers: Vec::new(),
        ai_narrative: None,
        detection_context: cryptotrace::types::DetectionContext::Forensics,
        engine_version: "0.2.0".into(),
        signature_db_version: "default".into(),
    };

    let prompt = cryptotrace::intelligence::narrative::build_prompt(
        result.algorithm.as_deref(),
        &result.detected_type,
        result.entropy,
        &format!("{:?}", result.risk_level),
        result.confidence,
        result.confidence_is_provisional,
        "entropy: 7.80, block_alignment: 0.85",
        result.weakness.as_deref(),
    );

    println!("=== AI Prompt ({} chars) ===", prompt.len());
    println!("{}", &prompt[..500.min(prompt.len())]);
    if prompt.len() > 500 {
        println!("... (truncated)");
    }

    let simulated_response = r#"{"summary":"SHA256 hash detected with medium confidence","confidence_statement":"94% calibrated confidence based on entropy and signal analysis","cve_mentions":["CVE-2023-1234"]}"#;
    let validated = cryptotrace::intelligence::narrative::validate_narrative(simulated_response);

    println!("\n=== Validated Response ===");
    match validated {
        Ok(narrative) => {
            println!("Summary: {}", narrative.summary);
            println!("Confidence: {}", narrative.confidence_statement);
        }
        Err(e) => eprintln!("Validation failed: {}", e),
    }
}
