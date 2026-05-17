# CryptoTrace

**Cryptographic Fingerprinting & Data Classification Engine**

CryptoTrace analyses files and strings to detect cryptographic fingerprints — hashes, encodings, compressed data, encrypted blobs, and embedded high-entropy payloads. It explains *why* something is flagged via signal breakdown, calibrated confidence scoring, recursive layer unwrapping, and optional AI narrative generation.

---

## Features

- **Hash detection** — MD5, SHA1, SHA256, SHA512, bcrypt, Argon2id, NTLM, UUID (with whitespace stripping and disambiguation)
- **Encoding detection** — Base64, Hex, URL Encoding, Base32 (with confidence scoring and decode preview)
- **Compression detection** — GZIP, BZ2, Zstd, XZ, ZIP magic bytes + resource-limited decompression with expansion ratio guard (100:1 max)
- **Encryption heuristics** — OpenSSL AES (`Salted__` prefix), RSA PEM headers, generic high-entropy + block alignment detection
- **Entropy analysis** — Shannon entropy (0.0–8.0) + 4KB sliding window with 2KB stride to find embedded high-entropy regions
- **Magic byte registry** — 50-entry YAML-driven signature database covering compression, documents, images, audio, video, executables, archives, disk images, cryptographic keys, fonts, databases, and bytecode formats
- **Recursive layer analysis** — unwraps nested encoding/compression with cycle detection, depth limit (10), timeout (30s), and expansion ratio guard
- **Calibrated confidence engine** — Platt scaling logistic regression (gradient descent with L2 regularization) trained on 6 signal features; includes fallback provisional scoring when no model is loaded
- **AI narrative generation** — optional per-analysis narrative from OpenAI, Anthropic, or local models (Ollama); structured JSON output with per-field hallucination validation
- **REST API** — axum-based HTTP server with `POST /analyze`, `GET /health`, `GET /version`; Bearer token auth and token-bucket rate limiting
- **Subprocess sandbox** — isolates risky parsers in a separate process with hard timeout and crash recovery
- **Risk classification** — Critical / High / Medium / Low / Unknown with category-based defaults and user override support
- **Audit logging** — structured tracing events for every analysis
- **Input sanitization** — size limits (50 MB files, 10 MB strings), null byte policy, path traversal prevention, symlink detection
- **CLI** — `analyze`, `update`, `version`, `cache`, `config`, `calibrate` commands via clap derive
- **JSON output** — machine-readable analysis results with all signals and metadata

---

## Installation

### Prerequisites

- **Rust 1.95.0** or later (stable toolchain)
- **Windows** (x86_64-pc-windows-msvc) — primary target

### Build from source

```bash
git clone https://github.com/your-org/cryptotrace.git
cd cryptotrace
cargo build --release
```

The release binary will be at `target/release/cryptotrace.exe` (~6.1 MB). A worker binary is also produced at `target/release/cryptotrace-worker.exe` (~826 KB) for subprocess isolation.

### Verify

```bash
cryptotrace version
```

Expected output:
```
CryptoTrace v0.1.0
Engine: 0.1.0
Signature DB: 1.0.0
```

---

## Usage

### Analyze a string

```bash
cryptotrace analyze "5f4dcc3b5aa765d61d8327deb882cf99"
```

Detects MD5 hash:

```
═══════════════════════════════════════
 CryptoTrace Analysis Report
═══════════════════════════════════════

 Input:      3f2cd8e57b096fe7e4a78a5627e34ca3
 Entropy:    3.80 / 8.00
 Risk Level: Critical
 Source:     String

 Detection:  MD5
 Type:       hash
 Confidence: 94% (calibrated)

 Signals:
   entropy            3.80
   block_alignment    0.00
   magic_bytes        0.00
   length_pattern     1.00
   charset_purity     1.00
   window_variance    0.00

 Weakness:   collision_vulnerable, rainbow_table_crackable

 Recommendation:
   Replace with bcrypt (cost ≥ 12) or Argon2id.

═══════════════════════════════════════
```

### Analyze a file

```bash
cryptotrace analyze suspicious_file.bin
```

If the path exists, it is read and analysed as a file.

### JSON output

```bash
cryptotrace analyze "5f4dcc3b5aa765d61d8327deb882cf99" --json
```

Returns structured JSON with all fields.

### Recursive analysis

```bash
cryptotrace analyze encoded_payload.bin --deep
```

Unwraps nested layers (Base64 → GZIP → ...) up to depth 10 with timeout and expansion ratio guards.

### Sandboxed analysis

```bash
cryptotrace analyze unknown.bin --sandbox
```

Runs the detection pipeline in an isolated subprocess with timeout and crash recovery.

### AI narrative

```bash
# Requires OPENAI_API_KEY or ANTHROPIC_API_KEY env var
cryptotrace analyze "5f4dcc3b5aa765d61d8327deb882cf99" --ai
```

Appends an AI-generated narrative (summary, risk reason, recommended action, confidence statement) to the output. Every field is validated for hallucination — CVEs must be real, summaries are sentence-limited, and risk reasons must reference actual signals.

### Calibrate confidence

```bash
# Generate synthetic training data
cryptotrace calibrate generate --samples 200

# Train a Platt scaling model
cryptotrace calibrate train --data calibration_data/train.csv

# Check model status
cryptotrace calibrate status
```

The calibration model is loaded at startup and used to produce calibrated confidence scores with per-signal attribution.

### Signature database management

```bash
# Check current version
cryptotrace update

# Import an update from a local file (air-gap mode)
cryptotrace update --from-file /path/to/updated-registry.yaml

# Roll back to previous version
cryptotrace update --rollback
```

### REST API server

```bash
# Start the API server (Ctrl+C to stop)
cryptotrace --api
```

By default listens on `127.0.0.1:8080`. Configure via `cryptotrace.toml`:

```toml
[api]
bind = "127.0.0.1:8080"
api_key = "your-secret-key"
rate_limit = 60
sandbox_enabled = false
```

```bash
# Health check
curl http://127.0.0.1:8080/health

# Analyze via API
curl -X POST http://127.0.0.1:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"input": "5f4dcc3b5aa765d61d8327deb882cf99", "input_type": "string"}'
```

### Cache and configuration

```bash
cryptotrace cache clear
cryptotrace config show
```

---

## Signal Breakdown

Each analysis returns a `SignalBreakdown` with these components:

| Signal | Range | Description |
|--------|-------|-------------|
| `entropy` | 0.0–8.0 | Shannon entropy of the input |
| `block_alignment` | 0.0–1.0 | How well data aligns to AES/RSA block sizes |
| `magic_bytes` | 0.0–1.0 | Confidence from signature registry match |
| `length_pattern` | 0.0–1.0 | How well length matches expected hash/encoding sizes |
| `charset_purity` | 0.0–1.0 | Portion of input matching expected character set |
| `window_variance` | 0.0+ | Variance in sliding-window entropy scores |
| `byte_distribution` | 0.0–1.0 | Uniformity of byte frequency distribution |

---

## Architecture

```
src/
├── main.rs                  # Binary entrypoint (CLI or --api server)
├── lib.rs                   # Crate root (public module exports)
├── cli.rs                   # CLI definition (clap derive)
├── types.rs                 # Core structs: DetectionResult, SignalBreakdown, etc.
├── error.rs                 # CryptoTraceError enum (thiserror)
├── workers.rs               # WorkerPool wrapper (backward compat)
├── cache.rs                 # LRU cache for dedup and AI narratives
├── update.rs                # Signature database update manager
├── analyzers/
│   ├── file.rs              # Full detection pipeline (+sandboxed variants)
│   ├── string.rs            # String-specific analysis
│   └── recursive.rs         # Recursive layer unwrapping
├── core/
│   ├── entropy.rs           # Shannon entropy + classification
│   ├── sliding_entropy.rs   # 4KB rolling-window entropy
│   ├── hashing.rs           # Hash format detection
│   ├── encoding.rs          # Encoding format detection
│   ├── compression.rs       # Compression detection + decompression
│   ├── encryption.rs        # Encryption heuristics
│   ├── calibration.rs       # Platt scaling logistic regression
│   └── confidence.rs        # Calibrated/provisional confidence engine
├── signatures/
│   ├── mod.rs               # Magic byte registry (YAML-driven)
│   └── default.yaml         # 50-entry built-in registry
├── intelligence/
│   ├── risk.rs              # Risk level resolution
│   ├── prompt.rs            # AI prompt builder (re-exports narrative)
│   ├── narrative.rs         # AI response validation + build_prompt
│   └── audit.rs             # Structured audit logging
├── providers/
│   └── mod.rs               # AiProvider trait (OpenAI/Anthropic/Local)
├── reports/
│   ├── terminal.rs          # Formatted terminal output
│   └── json.rs              # JSON serialization
├── sanitization/
│   ├── guard.rs             # InputGuard (size, null bytes, traversal)
│   └── sandbox.rs           # Subprocess isolation with timeout
├── api/
│   ├── mod.rs               # ApiConfig + run() with graceful shutdown
│   ├── routes.rs            # GET /health, GET /version, POST /analyze
│   ├── auth.rs              # Bearer token auth + rate limiter
│   └── errors.rs            # Structured JSON error responses
└── bin/
    └── worker.rs            # cryptotrace-worker binary
```

---

## Security

- **Air-gapped by default** — no network calls unless explicitly configured
- **All AI features opt-in** — disabled until a provider is configured in `cryptotrace.toml` or env var
- **Input limits** — 50 MB files, 10 MB strings, null bytes rejected in strings
- **Decompression guards** — 100:1 expansion ratio limit, 100 MB output cap
- **Recursion guards** — depth limit (10), timeout (30s), cycle detection via hash set
- **Sandbox isolation** — risky parsers run in isolated subprocesses with hard timeout and crash recovery
- **Structured AI output** — per-field JSON validation prevents hallucination (hallucinated CVEs, missing signal references)
- **API authentication** — Bearer token or X-API-Key header with configurable rate limiting

See [`SECURITY.md`](SECURITY.md) for the full security policy.

---

## Configuration

Create a `cryptotrace.toml` file in the working directory or in `%APPDATA%/cryptotrace/`:

```toml
[analysis]
context = "forensics"
max_file_size = 52428800
max_string_size = 10485760
deep = false

[signatures]
registry_path = ""
auto_update = false

[sandbox]
enabled = false
max_workers = 4
timeout_seconds = 30

[ai]
# provider = "openai"
# api_key = "sk-..."

[cache]
max_ai_entries = 100
dedup_enabled = true
max_dedup_entries = 1000

[api]
enabled = false
bind = "127.0.0.1:8080"
rate_limit = 60

[logging]
level = "info"
format = "pretty"
```

See [`cryptotrace.toml.example`](cryptotrace.toml.example) for a complete reference.

---

## Development

### Running tests

```bash
cargo test
```

94 tests covering all detection modules, calibration, sanitization, API server, sandbox, signatures, and update management.

### Building

```bash
cargo build                 # debug
cargo build --release       # release (LTO, stripped)
```

### Code style

```bash
cargo fmt
cargo clippy
```

---

## License

Apache 2.0. See [`LICENSE`](LICENSE).
