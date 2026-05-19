# Signal Attribution

This document explains how CryptoTrace computes confidence scores and how to interpret the signal breakdown in analysis results.

## Overview

CryptoTrace uses a multi-signal confidence engine that combines 7 independent signals into a single confidence score. Each signal measures a different property of the input data. The combination is weighted and calibrated to produce a probabilistic confidence estimate.

## Signal Definitions

### 1. Entropy (`entropy`)

Range: 0.0 – 1.0 (normalized from raw Shannon entropy 0.0–8.0)

Measures the randomness of byte distribution. High entropy suggests compressed or encrypted data. Low entropy suggests plaintext or structured data.

- **High (≥ 0.8):** Consistent with encrypted or compressed data
- **Medium (0.4–0.8):** Mixed content, partially encoded
- **Low (< 0.4):** Plaintext, structured data

*Limitation:* Entropy alone cannot distinguish encryption from compression.

### 2. Byte Distribution (`byte_distribution`)

Range: 0.0 – 1.0

Chi-square test of byte frequency uniformity. Only computed for inputs ≥ 5120 bytes. Uniform distribution suggests random data (encrypted/compressed). Skewed distribution suggests structured data (plaintext, code, headers).

### 3. Block Alignment (`block_alignment`)

Range: 0.0 – 1.0

How well the input length aligns to common cryptographic block sizes (16, 32, 64). Strong alignment suggests block cipher encryption (AES) or hash output. Weak alignment suggests arbitrary data.

- **1.0:** Length is a multiple of common block sizes
- **0.0:** Length does not match any block size

### 4. Magic Bytes (`magic_bytes`)

Range: 0.0 – 1.0

Confidence from the signature registry match. When the input starts with known magic bytes (e.g., `89 50 4E 47` for PNG), this signal is high. Values come from the YAML signature database (`signatures/default.yaml`).

### 5. Length Pattern (`length_pattern`)

Range: 0.0 – 1.0

How well the input length matches the expected length for a given algorithm. For example, MD5 expects exactly 32 hex characters. SHA256 expects 64. This is a high-precision signal when input length is exact.

### 6. Character Set Purity (`charset_purity`)

Range: 0.0 – 1.0 (None for binary inputs)

What fraction of characters match the expected character set. For hex strings, this is the fraction of `[0-9a-fA-F]` characters. For Base64, the fraction of `[A-Za-z0-9+/=]` characters.

### 7. Window Variance (`window_variance`)

Range: 0.0+ (unbounded)

Variance of entropy scores across 4KB sliding windows (2KB stride). Low variance (< 0.5) suggests uniform content. High variance (> 2.0) suggests mixed content with embedded payloads.

- **Low:** Single format throughout (plaintext, single encoding)
- **High:** Mixed content, embedded payloads

## Confidence Computation

### Step 1: Raw signal collection

Each detector (hash, encoding, compression, encryption) collects its own signal values. For example, an MD5 detector would find:
- High `length_pattern` (exactly 32 chars)
- High `charset_purity` (all hex characters)
- High `entropy` (~3.8 / 8.0)
- Low `block_alignment` (no alignment requirement)
- Zero `magic_bytes` (hashes have no magic bytes)

### Step 2: Weighted combination

```
heuristic_confidence = Σ(signal_i × weight_i) / Σ(weight_i)
```

Where weights are empirically validated against the test corpus.

### Step 3: Correlated signal cap

Signals that are not independent are capped to prevent double-counting:
- `entropy` + `byte_distribution` combined cap: ≤ 0.35

This prevents "entropy is high, byte distribution is uniform → must be encryption" from dominating the score. These signals are correlated — high entropy typically implies uniform byte distribution.

### Step 4: Platt scaling calibration

If a calibration model is loaded, the heuristic score is transformed:
```
calibrated_confidence = 1 / (1 + exp(heuristic_score × weight + bias))
```

This maps heuristic scores to true probabilities. For example, a calibrated score of 0.94 means "94% probability this classification is correct."

### Step 5: Provisional fallback

If no calibration model is loaded, the heuristic score is used directly with `confidence_is_provisional: true`.

## Reading the Output

### Example: MD5 Hash Detection

```json
{
  "confidence": 0.98,
  "calibrated": true,
  "heuristic_raw": 0.97,
  "calibration_samples": 1247,
  "signals": {
    "entropy": 0.45,
    "length_pattern": 1.0,
    "charset_purity": 1.0,
    "block_alignment": 0.3,
    "magic_bytes": 0.0
  },
  "primary_drivers": ["length_pattern", "charset_purity"],
  "conflicting_signals": ["magic_bytes"],
  "decision_trace": "Length pattern and charset purity strongly indicate hex-encoded SHA256. Magic byte match is 0 — expected. Confidence weighted toward positive signals."
}
```

**Interpretation:**
- `primary_drivers`: These signals contributed most to the decision
- `conflicting_signals`: The `magic_bytes` signal was low, but this is expected for hashes (no magic bytes)
- `decision_trace`: Human-readable explanation of how the final confidence was reached
- `calibrated: true`: The score of 0.98 is a true probability estimate
- `calibration_samples`: The model was trained on 1247 samples

### Common patterns

| Pattern | Signals | Interpretation |
|---------|---------|----------------|
| All signals high, no conflicts | Strong, unambiguous detection | High confidence |
| One signal low but explained | Expected weak signal (e.g., no magic bytes for hashes) | Confidence still valid |
| Multiple conflicting signals | Ambiguous input or adversarial | Lower confidence, flagged in output |
| High entropy + high block alignment + no magic | Possible encryption, no known prefix | Max confidence 0.65 |
