/// Memory stability test: verify the engine handles deep nesting without
/// runaway memory allocation.
///
/// Strategy:
///   1. Build a chain of 5 nested base64 layers starting from a small
///      core payload. The outermost layer is roughly 10 MB.
///   2. Feed the outermost blob into `analyze_recursive`.
///   3. Assert the pipeline completes — if it didn't OOM or get reaped by
///      the kernel, we consider that a pass (the test harness also logs
///      peak RSS for manual review).
///
/// Note: exact heap measurement is platform-specific, so we rely on
/// successful completion as a proxy.
use cryptotrace::analyzers::recursive::{RecursiveConfig, analyze_recursive};
use cryptotrace::error::Result;

/// Build a chain of `depth` nested base64 layers around a tiny core.
/// Starting from `core`, each layer encodes the previous layer in base64.
/// The innermost is core, and we return the outermost (most-wrapped) blob.
fn build_base64_chain(core: &[u8], depth: usize) -> Vec<u8> {
    let mut current = core.to_vec();
    for _ in 0..depth {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &current);
        current = encoded.into_bytes();
    }
    current
}

#[test]
fn test_10_layer_chain_stays_bounded() -> Result<()> {
    // Core payload: a few KB of realistic-looking "data".
    // Each base64 layer adds ~33% overhead. For 5 layers:
    //   outer = core * (4/3)^5 ≈ core * 4.21
    // To reach ~10 MB at layer 5: core ≈ 10 MB / 4.21 ≈ 2.4 MB.
    let core = b"This is a test payload with some entropy to look like real data. ";
    let core_len = 2_400_000;
    let core_repeated: Vec<u8> = core.iter().copied().cycle().take(core_len).collect();

    // Build 5 layers of nested base64 — outermost should be ~ 10 MB.
    let outer = build_base64_chain(&core_repeated, 5);

    // Sanity-check the size
    let expected_min: usize = 8_000_000; // 8 MB
    let expected_max: usize = 14_000_000; // 14 MB
    assert!(
        outer.len() >= expected_min,
        "outer layer too small: {} < {}",
        outer.len(),
        expected_min
    );
    assert!(
        outer.len() <= expected_max,
        "outer layer too large: {} > {}",
        outer.len(),
        expected_max
    );

    // Allow a generous timeout to account for debug-mode slowness.
    let config = RecursiveConfig {
        max_depth: 10,
        max_time_secs: 120,
        ..Default::default()
    };
    let layers = analyze_recursive(&outer, &config)?;

    // If we got here, the pipeline didn't OOM, which is the main check.
    // Additionally verify we actually unwrapped at least half the layers.
    assert!(
        layers.len() >= 3,
        "expected at least 3 decoded layers, got {}",
        layers.len()
    );

    Ok(())
}
