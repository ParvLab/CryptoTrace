# Calibration Datasets

Each CSV file contains labeled samples for training the Platt-scaling
calibration model. The model maps raw signal vectors to calibrated
probabilities.

## Format

All files share the same columns:

| Column | Type | Range | Description |
|--------|------|-------|-------------|
| `entropy` | float | 0.0–8.0 | Shannon entropy |
| `block_alignment` | float | 0.0–1.0 | AES/RSA block alignment score |
| `magic_bytes` | float | 0.0–1.0 | Magic byte match confidence |
| `length_pattern` | float | 0.0–1.0 | Length matches expected format |
| `charset_purity` | float | 0.0–1.0 | Character set consistency |
| `window_variance` | float | 0.0+ | Sliding-window entropy variance |
| `label` | int | 0 or 1 | 1 = cryptographic artifact, 0 = benign |
| `detected_type` | string | — | Ground-truth type (hash, encoding, compression, encrypted, plaintext) |

## Files

- `train.csv` — training dataset
- `test.csv` — held-out test set for accuracy evaluation

## Generating Datasets

Run `cargo run --release calibrate generate` to create synthetic training data
from known signal profiles for each detection type.
