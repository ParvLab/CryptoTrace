# CryptoTrace — Implementation Plan
### Cryptographic Fingerprinting & Data Classification Engine

> **Version:** 3.0 | **Status:** Historical Planning Document (phases 1–7 complete) | **Classification:** Internal Planning Document
> **License:** Apache 2.0 (engine) / Community Data License Agreement (signatures & samples)
> **Language:** Rust (100% — from Day 1)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture](#2-architecture)
3. [Technology Stack](#3-technology-stack)
4. [AI Integration Strategy](#4-ai-integration-strategy)
5. [Folder Structure](#5-folder-structure)
6. [Phase-by-Phase Implementation Plan](#6-phase-by-phase-implementation-plan)
   - [Phase 1 — Foundation & MVP](#phase-1--foundation--mvp-weeks-12)
   - [Phase 2 — File Intelligence & Compression](#phase-2--file-intelligence--compression-weeks-34)
   - [Phase 3 — Advanced Detection & Confidence Engine](#phase-3--advanced-detection--confidence-engine-weeks-57)
   - [Phase 4 — AI Intelligence Layer](#phase-4--ai-intelligence-layer-weeks-810)
   - [Phase 5 — Recursive Layer Analyzer](#phase-5--recursive-layer-analyzer-weeks-1112)
   - [Phase 6 — API, Explainability & Format Inference](#phase-6--api-explainability--format-inference-weeks-1314)
   - [Phase 7 — Ecosystem & Open Source Launch](#phase-7--ecosystem--open-source-launch-weeks-1516)
7. [Module Specifications](#7-module-specifications)
8. [Detection Techniques Reference](#8-detection-techniques-reference)
9. [Prompt Engineering Design](#9-prompt-engineering-design)
10. [Testing & Validation Strategy](#10-testing--validation-strategy)
11. [Open Source Strategy](#11-open-source-strategy)
12. [Risk Register](#12-risk-register)

---

## 1. Executive Summary

CryptoTrace is a **cryptographic fingerprinting and data classification engine** — not a decryption tool, not an antivirus, not a guarantee of safety. Its core value is forensic intelligence: identifying *what kind* of data you have, *how it was protected*, and *what risk that implies*.

**Scope and honest limitations:**
- CryptoTrace performs **classification, not decryption**. It tells you what something *might be*, not what it *is*.
- Detection is probabilistic. Confidence scores are estimates with documented false-positive rates — never absolute certainty.
- Malware uses hundreds of obfuscation techniques (XOR, rolling ciphers, custom base encodings, packers, multi-layer wrapping). Base64 is one of many. CryptoTrace covers common patterns but cannot detect everything.
- Air-gapped operation is supported **only when all cloud-dependent features are explicitly disabled** (AI providers, signature updates, VirusTotal integration). The tool ships with all cloud features off by default.
- The tool itself is an attack surface. SOC analysts scanning attacker-controlled files means crafted inputs may attempt to exploit parsing libraries, exhaust resources, or evade detection. Input sanitization (see Section 2) is a security boundary, not a suggestion.

**Target users:**
- SOC analysts and blue team practitioners
- Malware researchers and reverse engineers
- Security auditors and compliance teams
- CTF players and security students

**What CryptoTrace does:**
- Classify unknown data with confidence scoring (with documented FP rates per class)
- Detect layered encoding and encryption chains
- Flag algorithmic weaknesses and compliance risks
- Provide AI-generated forensic narrative reports (opt-in, fully offline-capable)
- Operate without any cloud dependency when AI, update, and integration features are disabled

**What CryptoTrace does NOT do:**
- Decrypt or decode protected data
- Guarantee detection accuracy on adversarial inputs
- Replace professional forensic analysis
- Protect itself from all possible attacks (see Risk Register Section 12)

---

## 2. Architecture

```
┌─────────────────────────────────────┐
│           Input Engine              │
│  (files, strings, binary, PCAP)     │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│       Input Sanitization Layer      │
│  (size limits, null byte policy,    │
│   format validation, symlink check, │
│   OS sandbox for untrusted blobs)   │
└──────────────┬──────────────────────┘
               │
     ┌─────────┴──────────┐
     │                     │
┌────▼────────┐    ┌──────▼────────┐
│  File       │    │  String       │
│  Analyzer   │    │  Analyzer     │
└────┬────────┘    └──────┬────────┘
     └─────────┬──────────┘
               │
┌──────────────▼──────────────────────┐
│         Detection Engine            │
└──┬──────────┬──────────┬────────────┘
   │          │          │
┌──▼───┐  ┌──▼───┐  ┌───▼────┐
│Hash  │  │Entropy│  │Encoding│
│Scan  │  │Engine │  │Detect  │
└──┬───┘  └──┬───┘  └───┬────┘
   │     ┌───┴──────────┘
   │     │
   │ ┌───▼────────────────────┐
   │ │ Sliding-Window Entropy │  ← 4KB rolling windows for mixed payloads
   │ │ Analyzer               │
   │ └────────────────────────┘
   │          │
┌──▼──────────▼──────────▼────────────┐
│    Multi-Signal Confidence Engine   │
│  (weighted: entropy + byte dist +   │
│   block align + magic + length)     │
│  CORRELATED SIGNAL WEIGHT CAP: 0.35 │
│  RAW SIGNAL BREAKDOWN EXPOSED       │  ← explainability
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   Calibration Layer                 │  ← Platt scaling / isotonic regression
│   (heuristic scores → probabilities)│
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   Recursive Layer Analyzer          │
│   (MAX_DEPTH=10, MAX_TIME=30s,      │
│    MAX_EXPANSION_RATIO=100:1,       │  ← new: compression bomb defense
│    cycle detect via hash, no full   │
│    decoded byte retention)          │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Intelligence Core              │
│  (risk classification, weakness     │
│   mapping, compliance flagging,     │
│   audit logging)                    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      AI Narrative Layer             │
│  (pluggable providers: OpenAI,      │
│   Anthropic, Ollama — DISABLED by   │
│   default, fully opt-in)            │
│  STRUCTURED CONSTRAINED GENERATION  │  ← schema-validated output fields
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Report Generator               │
│  (JSON, CLI, HTML, layer tree)      │
│  + signal attribution breakdown     │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      REST API Layer                 │
│  (async job pattern: POST /jobs,    │
│   GET /jobs/:id, auth, rate limit)  │
└─────────────────────────────────────┘
```

### Cross-Cutting Components

```
   ┌─────────────────────────────┐
   │    Audit & Logging Layer    │
   │   (structured JSON logs,    │
   │    traceable decisions,     │
   │    no PII in logs)          │
   └─────────────────────────────┘

   ┌─────────────────────────────┐
   │    Caching Layer            │
   │   (SHA256 input dedup cache,│
   │    in-memory LRU,           │
   │    configurable max size)   │
   └─────────────────────────────┘

   ┌─────────────────────────────┐
   │    Parser Isolation Layer   │
   │   (subprocess workers for   │
   │    risky parsing: libmagic, │
   │    decompression, ASN.1,    │
   │    image codecs)            │
   └─────────────────────────────┘
```

### Threat Context Model

CryptoTrace operates across three threat contexts, user-selectable via `--context` flag or config:

1. **Malware payload analysis** — high FP tolerance. Threshold: any risk > LOW triggers alert.
2. **Password/credential auditing** — low FP tolerance. Only HIGH/CRITICAL triggers alert.
3. **Suspicious file forensics** — balanced. All detections reported with confidence and FP risk.

If an input matches multiple contexts, the tool applies the most conservative (highest-sensitivity) thresholds and reports the context conflict.

---

## 3. Technology Stack

### Rust-From-Day-1 — No Python, No Dual Stack

CryptoTrace is built entirely in Rust from Day 1. Rust's ownership model eliminates memory safety vulnerabilities in parsing untrusted binary data — the single most critical requirement for a forensic tool that processes attacker-controlled files. Python's C-extension stack cannot provide this guarantee.

**Why not Python-first with migration:**
- The detection engine processes untrusted binary blobs from Day 1 — Rust's memory safety is a requirement, not an optimization
- Porting from Python to Rust mid-project introduces regression risk and delays
- Rust's type system catches entire classes of bugs (null pointer, buffer overflow, use-after-free) at compile time that Python would find in production
- Single portable binary deployment (no Python runtime dependency) from the first release

**Language:** Rust (edition 2024+)

### Core Rust Dependencies

| Purpose | Crate | Justification |
|---------|-------|---------------|
| Async runtime | `tokio` | Industry standard async I/O and task scheduling |
| HTTP server | `axum` | Modular, tokio-native web framework |
| CLI interface | `clap` | Derive-based argument parsing, shell completion generation |
| Serialization | `serde` + `serde_json` | Zero-copy deserialization, schema validation |
| Configuration | `toml` + `serde` | Typed config deserialization |
| Cryptography | `ring` | FIPS 140-2 ready, constant-time, no OpenSSL dependency |
| Binary parsing | `nom` | Zero-copy, combinator-based parser framework |
| Entropy / stats | custom + `statrs` | Shannon entropy, chi-square tests, Platt scaling |
| Compression | `flate2`, `brotli`, `lzma`, `zstd` | Decompression with resource limits |
| Process isolation | `std::process::Command` + caps | Native sandboxing — no Docker dependency |
| Logging | `tracing` | Structured, async-aware diagnostic logging |
| Testing | `cargo test`, `proptest` | Property-based fuzz testing built in |

### OS-Level Dependencies

| Dependency | Notes |
|------------|-------|
| None beyond Rust toolchain | Statically link everything. Single binary target. |

### Why No Docker for Sandboxing

Rust's `Command` + OS-native capabilities (seccomp/LSM on Linux, Job Objects on Windows, sandbox-exec on macOS) provide process-level isolation without Docker. This eliminates a deployment dependency and simplifies air-gap scenarios.

---

## 4. AI Integration Strategy

### Design Principle: AI Is an Enhancement, Not a Dependency — DISABLED BY DEFAULT

CryptoTrace's core functionality — entropy scoring, hash detection, pattern matching — requires zero AI. The AI layer provides the forensic narrative report on top of the structured detection result. This means:
- The tool ships with AI features **disabled by default**
- Users must explicitly opt in via `cryptotrace.toml` → `[ai] enabled = true`
- The tool works fully offline without any model configured
- No API key is required to use the tool's core functionality

### Architecture: Bring-Your-Own-Model (Async)

```rust
// providers/base.rs
#[async_trait]
pub trait AiProvider: Send + Sync {
    async fn complete(&self, system: &str, user: &str) -> Result<String, AiError>;
}

// Supported providers
// providers/openai.rs     → GPT-4o family, GPT-4-turbo family
// providers/anthropic.rs  → Claude Sonnet family, Claude Haiku family
// providers/ollama.rs     → Local models (Llama3, Mistral, Phi3)
// providers/mod.rs        → Config-driven provider selection (factory)
```

**Provider family names (NOT version-specific model IDs):**
- OpenAI: `gpt-4o-family`, `gpt-4-turbo-family`, `gpt-3.5-turbo-family`
- Anthropic: `claude-sonnet-family`, `claude-haiku-family`
- Ollama: any locally served model name (passed through as-is)

### Air-Gap and Privacy

SOC analysts and malware researchers cannot send payloads to cloud services.
- **Ollama support means the AI narrative layer can run fully air-gapped** — users pre-download models while internet-connected, then transfer via USB to the air-gapped system.
- If OpenAI/Anthropic providers are used, the tool is NOT air-gapped.

### AI Output Caching

Cache AI narratives by input SHA256 hash. Configurable TTL (default: 7 days). Cache stored locally in `~/.cryptotrace/ai_cache/`.

### Error Handling

- **Timeouts:** retry once with exponential backoff, then skip AI narrative
- **Rate limits (HTTP 429):** queue request with `Retry-After` header respect
- **Content policy blocks:** log error, return report without AI narrative
- **Provider unavailable:** return "AI narrative unavailable — provider offline"
- **Model deprecation (410):** log warning, suggest provider config update

### Prompt Injection Defense

1. **Structured input only.** AI NEVER receives raw user input — only structured `DetectionResult` JSON.
2. **Output validation filter.** Scan for instruction-like patterns ("ignore previous instructions", "system prompt"). If detected, discard and log "Possible prompt injection attempt."
3. **Temperature 0.1** (configurable) reduces injection success rate.
4. **Never include raw user input text** in the system prompt context.

### Structured Constrained Generation (Not Freeform Narrative)

Instead of a freeform text response, the AI returns a structured JSON object. Each field is validated independently against known-safe values and value types.

```
SYSTEM:
You are a senior cryptographic forensics analyst.
You receive structured JSON output from CryptoTrace, a detection engine.
Your job is to write a concise forensic intelligence report.

You MUST respond with valid JSON following this exact schema:
{
  "summary": "string, max 150 words, plain English",
  "risk_reason": "string, explain WHY this algorithm is risky",
  "recommended_action": "string, exactly ONE next action, not a list",
  "confidence_statement": "string, cite the detection confidence score"
}

Rules:
- Never guess beyond what the data shows
- Always cite the confidence score when making claims
- If risk_level is HIGH or CRITICAL, lead with the risk reason
- Explain WHY an algorithm is weak, not just that it is
- Write in plain English. No markdown, no bullet points, no escape characters.
- Do NOT invent algorithms, CVE IDs, attack techniques, or data not present in the input JSON.
- Do NOT include algorithms absent from the "layers" or "algorithm" fields of the input.
- The "layers" array may contain nested objects — analyze ALL layers and describe the full chain.
```

The structured JSON passed to the model:

```json
{
  "detected_type": "hash",
  "algorithm": "MD5",
  "confidence": 0.98,
  "entropy": 3.8,
  "risk_level": "CRITICAL",
  "weakness": "collision_vulnerable",
  "layers": [
    {"depth": 0, "type": "encoding", "algorithm": "Base64", "confidence": 0.99},
    {"depth": 1, "type": "compression", "algorithm": "GZIP", "confidence": 0.97}
  ],
  "recommendations": []
}
```

**Hallucination validation (per-field):**
1. `summary` — check word count, strip markdown
2. `risk_reason` — extract all algorithm-like words, verify each exists in `DetectionResult.algorithm` or `layers[].algorithm`
3. `recommended_action` — verify it references only algorithms present in the input
4. `confidence_statement` — verify cited confidence value matches the detection result

If ANY field references an algorithm not present in the input, discard the ENTIRE response and log structured hallucination alert with the offending field name.

### Provider Configuration

```toml
[ai]
enabled = false
provider = "ollama"
model_family = "llama3"
base_url = "http://localhost:11434"
max_words = 150
temperature = 0.1
max_tokens = 512
response_timeout_seconds = 30

[ai.cache]
enabled = true
ttl_days = 7
max_entries = 10000
```

### Community Provider Registry

The repository includes `cryptotrace.providers.json` — all additions require maintainer security review to prevent malicious provider configurations.

---

## 5. Folder Structure

```
cryptotrace/
│
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── Makefile
├── LICENSE
├── SECURITY.md
├── .gitignore
│
├── src/
│   ├── main.rs                   # CLI entrypoint
│   │
│   ├── core/
│   │   ├── entropy.rs            # Shannon entropy engine
│   │   ├── sliding_entropy.rs    # 4KB rolling-window entropy analyzer
│   │   ├── hashing.rs            # Hash detection (MD5, SHA*, bcrypt, Argon2)
│   │   ├── encoding.rs           # Base64, Hex, Base32, Base58, URL encoding
│   │   ├── compression.rs        # ZIP, GZIP, Brotli, Zlib, RAR detection
│   │   ├── encryption.rs         # AES, RSA, ChaCha20 heuristics
│   │   └── confidence.rs         # Multi-signal engine + Platt calibration
│   │
│   ├── analyzers/
│   │   ├── file.rs               # File-based input handling
│   │   ├── string.rs             # String-based input handling
│   │   └── recursive.rs          # Layer unwrapping (depth, timeout, ratio)
│   │
│   ├── sanitization/
│   │   ├── guard.rs              # Size limits, null byte policy, symlink check
│   │   └── sandbox.rs            # OS-level sandbox (seccomp, Job, XPC)
│   │
│   ├── providers/
│   │   ├── mod.rs                # Provider trait + factory
│   │   ├── openai.rs             # OpenAI provider
│   │   ├── anthropic.rs          # Anthropic provider
│   │   ├── ollama.rs             # Ollama provider
│   │   └── cache.rs              # AI output cache
│   │
│   ├── intelligence/
│   │   ├── risk.rs               # Algorithm → risk level mapping
│   │   ├── prompt.rs             # Prompt builder + response validator
│   │   └── audit.rs              # Structured audit trail
│   │
│   ├── signatures/
│   │   ├── magic.rs              # Magic byte registry loader
│   │   ├── hash_patterns.rs      # Hash pattern registry loader
│   │   └── encoding_patterns.rs  # Encoding pattern registry loader
│   │
│   ├── cli.rs                    # clap-based command definitions
│   │
│   ├── api/
│   │   ├── mod.rs                # axum router + middleware
│   │   ├── auth.rs               # API key authentication
│   │   ├── rate_limit.rs         # Token bucket rate limiter
│   │   └── jobs.rs               # Async job queue (POST/GET /jobs/)
│   │
│   ├── reports/
│   │   ├── json.rs               # JSON report serializer
│   │   ├── terminal.rs           # rich-like terminal output
│   │   └── html.rs               # HTML report generator
│   │
│   ├── cache.rs                  # SHA256-based LRU input cache
│   └── workers.rs                # Parser isolation subprocess manager
│
├── signatures/                   # GPG-signed external detection data
│   ├── magic_bytes.yaml
│   ├── hash_patterns.yaml
│   ├── encoding_patterns.yaml
│   └── cve_map.yaml
│
├── samples/                      # SYNTHETIC test corpus only
│   ├── hashes/
│   ├── encodings/
│   ├── encrypted/
│   ├── compressed/
│   └── adversarial/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── accuracy/
│   ├── fuzz/
│   └── adversarial/
│
├── docs/
│   ├── GETTING_STARTED.md
│   ├── CLI_REFERENCE.md
│   ├── API_REFERENCE.md
│   ├── ACCURACY.md
│   ├── AIR_GAP_GUIDE.md
│   ├── SIGNAL_ATTRIBUTION.md    # How to read explainable confidence breakdowns
│   └── CONTRIBUTING.md
│
├── cryptotrace.providers.json
├── cryptotrace.toml.example
└── scripts/
    ├── release.sh
    ├── benchmark.sh
    └── update-signatures.sh
```

---

## 6. Phase-by-Phase Implementation Plan

---

### Phase 1 — Foundation & MVP (Weeks 1–2)

**Goal:** A working CLI tool that correctly detects common hashes and Base64 encoding with entropy scoring and sliding-window analysis. Ship something real in Rust.

---

#### Step 1.1 — Project Bootstrap

- Initialize Cargo project with the folder structure defined in Section 5
- Configure `rust-toolchain.toml` (edition 2024)
- Add all Phase 1 crate dependencies to `Cargo.toml`
- Create `cryptotrace.toml.example` with all config keys documented (AI disabled by default)
- Set up linting (`clippy` + `rustfmt`) in CI
- Set up CI pipeline: `cargo check` → `cargo clippy` → `cargo test` → `cargo build --release`
- Create LICENSE, SECURITY.md, .gitignore

**Deliverable:** `cargo build` succeeds → `cargo test` passes on empty test suite → `cryptotrace --help` works → CI green

---

#### Step 1.2 — Input Sanitization Layer

Implement `src/sanitization/guard.rs` and `src/sanitization/sandbox.rs`:

- Enforce maximum input size (default: 50MB for files, 10MB for strings — configurable)
- Null byte policy: reject string inputs containing null bytes (`SanitizationError`). Pass binary inputs with a warning flag. Do NOT strip null bytes.
- Symlink-aware path validation: `std::fs::canonicalize()` to resolve symlinks, then verify resolved path stays within the allowed base directory.
- OS-level sandboxing: `sandbox.rs` abstracts platform-specific isolation. On Linux: seccomp-bpf + Landlock LSM. On Windows: Job Object + restricted token. On macOS: sandbox-exec. No Docker fallback needed — Rust's `Command` provides native process isolation.
- Return a `SanitizedInput` struct. All downstream modules consume this — never raw input. If `safe == false`, return `Err(SanitizationError)`.

```rust
#[derive(Debug)]
pub struct SanitizedInput {
    pub raw_bytes: Vec<u8>,
    pub source_type: SourceType,    // File | String | Binary
    pub original_length: usize,
    pub was_truncated: bool,
    pub safe: bool,
    pub has_null_bytes: bool,
    pub resolved_path: Option<PathBuf>,
}
```

**Deliverable:** `src/sanitization/` module with property tests covering: oversized input, null bytes, directory traversal, symlink attacks, valid inputs, sandbox fallback behavior.

---

#### Step 1.3 — Entropy Engine (Global + Sliding-Window)

Implement `src/core/entropy.rs` and `src/core/sliding_entropy.rs`:

- **Global entropy:** Shannon entropy over full byte distribution. Return score (0.0–8.0), byte frequency histogram.
- **Sliding-window entropy:** 4KB rolling windows with 2KB stride. Expose:
  - `window_entropy_scores: Vec<f64>` — per-window entropy values
  - `max_window_entropy` — highest local entropy peak
  - `entropy_variance` — variance across windows (low = uniform, high = mixed content)
  - `embedded_regions: Vec<OffsetRange>` — regions where entropy exceeds a configurable threshold (default: 7.0)
- Classification thresholds (configurable via `cryptotrace.toml` → `[entropy.thresholds]`): `< 3.5` = plaintext/structured, `3.5–6.0` = mixed/partially encoded, `6.0–7.5` = compressed/encoded, `> 7.5` = high entropy.
- **Critical:** High entropy alone is NOT encryption. Entropy > 7.5 = "high_entropy — type unknown" with max confidence 0.65.

**Deliverable:** `src/core/entropy.rs` and `src/core/sliding_entropy.rs` with unit tests covering: plaintext, Base64, high-entropy binary, PNG images, short strings, mixed-content payloads (plaintext + encrypted + padding).

---

#### Step 1.4 — Hash Detection Module

Implement `src/core/hashing.rs`:

**Length + Hex detectors:**

| Algorithm | Length | Char Set | Additional | Notes |
|-----------|--------|----------|------------|-------|
| MD5 | 32 | `[0-9a-fA-F]` | UUID disambiguation | UUID (no dashes) also 32 hex chars |
| SHA1 | 40 | `[0-9a-fA-F]` | Strip whitespace | sha1sum output includes filename |
| SHA256 | 64 | `[0-9a-fA-F]` | — | |
| SHA512 | 128 | `[0-9a-fA-F]` | — | |

**Prefix detectors:**

| Algorithm | Prefix | Target Precision |
|-----------|--------|-----------------|
| bcrypt | `$2a$`, `$2b$`, `$2y$` | 99% |
| Argon2id | `$argon2id$v=19$` | 99% |
| Argon2i | `$argon2i$v=19$` | 99% |
| PBKDF2 | No standard prefix | 80% (documented lower) |

**Legacy detection:**

| Algorithm | Length | Char Set | Notes |
|-----------|--------|----------|-------|
| NTLM | 32 | `[0-9a-fA-F]` | Uppercase-only hex |
| LM Hash | 32 | `[0-9a-fA-F]` | Split into 16-char halves |

**Deliverable:** `src/core/hashing.rs` with property tests for each class, UUID vs MD5 disambiguation test.

---

#### Step 1.5 — Encoding Detection Module

Implement `src/core/encoding.rs`:

- **Base64:** Confidence = computed score (charset * 0.3 + padding * 0.2 + decode * 0.4 + OpenSSL prefix * 0.1)
- **Hex:** `[0-9a-fA-F]`, even length, no padding
- **Base32:** `[A-Z2-7=]`, length multiple of 8
- **Base58:** Bitcoin alphabet (no `0`, `O`, `I`, `l`)
- **Base85 / Base91:** Common in malware
- **URL Encoding:** `%XX` patterns

All detectors attempt decode and return preview (truncated to 64 bytes) when confidence > 0.7.

**Deliverable:** `src/core/encoding.rs` with unit tests.

---

#### Step 1.6 — Basic Confidence Engine

*Simplified version. Full multi-signal + calibration ships in Phase 3.*

```
confidence = (signal_strength × 0.5) + (entropy_consistency × 0.3) + (length_match × 0.2)
```

Weights are provisional — exposed as `confidence_is_provisional: true` in output. Replaced in Phase 3 with empirically validated signals + Platt calibration.

**Deliverable:** `src/core/confidence.rs` with documented weight rationale.

---

#### Step 1.7 — CLI Interface

Implement `src/cli.rs` using `clap`:

```bash
cryptotrace analyze <input>              # Analyze string or file
cryptotrace analyze <file> --context     # malware|password|forensics
cryptotrace analyze <file> --deep        # Enable recursive analysis
cryptotrace analyze <file> --json        # Output raw JSON
cryptotrace analyze <file> --ai          # AI narrative (ERROR if not configured)
cryptotrace update                       # GPG-verified signature update
cryptotrace update --rollback            # Revert signature DB
cryptotrace version                      # Engine + signature DB versions
cryptotrace cache clear                  # Clear AI output cache
cryptotrace config show                  # Show config (redact secrets)
```

Terminal output:

```
═══════════════════════════════════════
 CryptoTrace Analysis Report
═══════════════════════════════════════

 Input:       5f4dcc3b5aa765d61d8327deb882cf99
 Entropy:     3.80 / 8.00  [global]
 Window:      3.72 / 8.00  [max local — uniform]
 Risk Level:  CRITICAL
 Context:     forensics

 Detection:   MD5 Hash
 Confidence:  98% (provisional — Phase 1 engine)
 FP Risk:     2.1%
 Weakness:    Collision vulnerable — rainbow table crackable

 Signals:
   entropy            0.91
   block_alignment    0.00
   magic_bytes        0.00
   length_pattern     1.00
   charset_purity     1.00

 Recommendation:
 Replace with bcrypt (cost ≥ 12) or Argon2id.

═══════════════════════════════════════
```

**Deliverable:** Full CLI with `--json`, `--deep`, `--context` flags working. Signal breakdown exposed in all output formats.

---

#### Phase 1 Exit Criteria

- [ ] Correctly detects MD5, SHA1, SHA256, SHA512, bcrypt, Argon2, PBKDF2, NTLM
- [ ] UUID vs MD5 disambiguation working
- [ ] Correctly detects Base64, Hex, Base32, Base58, Base85, Base91, URL encoding
- [ ] Global entropy scoring works (PNG, short strings, binary)
- [ ] Sliding-window entropy correctly identifies mixed-content payloads
- [ ] Input sanitization blocks: oversized, null bytes in strings, directory traversal, symlinks
- [ ] OS-level sandboxing works on Linux (seccomp) and Windows (Job Object)
- [ ] CLI outputs formatted report + raw JSON + signal breakdown
- [ ] FP rate on 200+ sample plaintext test set < 5%
- [ ] Signal breakdown exposed in all output formats
- [ ] CI pipeline green (`cargo check` → `clippy` → `test` → `build --release`)

---

### Phase 2 — File Intelligence & Compression (Weeks 3–4)

**Goal:** Extend detection to binary files, magic bytes with hierarchical format inference, and compressed data formats.

---

#### Step 2.1 — Magic Byte Registry + Hierarchical Format Inference

Build `signatures/magic_bytes.yaml` as a structured registry (100+ entries). **Add hierarchical format inference for overlapping formats:**

```yaml
version: "1.0.0"

signatures:
  - id: zip
    name: "ZIP Archive"
    magic_bytes: "504B0304"
    offset: 0
    category: compression
    risk_level: LOW
    subtypes:                       # ← hierarchical inference
      - id: ooxml
        name: "Office Open XML"
        detect: "inspect for [Content_Types].xml at offset 30"
      - id: apk
        name: "Android Package"
        detect: "inspect AndroidManifest.xml in central directory"
      - id: jar
        name: "Java Archive"
        detect: "inspect META-INF/MANIFEST.MF in central directory"
      - id: epub
        name: "EPUB eBook"
        detect: "inspect mimetype entry at offset 0"
    notes: "PKZIP format. Many subtypes share the same magic bytes — inspect internal structure for classification."
```

**Minimum coverage (100+ entries):**
- Compression: GZIP, ZIP, Zlib, Brotli, Zstd, LZ4, RAR, 7z, XZ, BZ2, LZH, CAB, ARJ
- Executables: PE, ELF, Mach-O, NE
- Encryption: OpenSSL `Salted__`, GPG armored, GPG binary, TrueCrypt/VeraCrypt
- Databases: SQLite, LevelDB, RocksDB, LMDB, BDB
- Archives: TAR, ISO, CPIO, DMG, VHD, VMDK, QCOW2
- Documents: PDF, OLE2, OOXML subtypes

**Deliverable:** `signatures/magic_bytes.yaml` with 100+ entries + subtype inference, `src/signatures/magic.rs`

---

#### Step 2.2 — File Analyzer

Implement `src/analyzers/file.rs`:

- File type detection using magic byte registry with `python-magic`-like library (`tree_magic_mini` or similar pure-Rust MIME detection)
- **Conflict resolution:** magic byte registry takes precedence; both sources reported with attribution
- Binary vs text classification
- Embedded content detection (all through sanitization layer)
- Metadata extraction: file size only — no EXIF, no network calls

**Deliverable:** `src/analyzers/file.rs` supporting `.txt`, `.bin`, `.json`, `.log`, `.pcap`

---

#### Step 2.3 — Compression Detection

Implement `src/core/compression.rs`:

- Magic byte matching + header structure validation
- Decompression attempt for confidence verification (isolated try/except)
- Size ratio heuristics
- **Resource-limited decompression:** max 256MB per attempt, max 5s, max file handle 1

**Deliverable:** Compression detection for GZIP, ZIP, Zlib, Brotli, LZ4, BZ2, Zstd, XZ

---

#### Step 2.4 — Signature Update Mechanism (GPG-Verified + Provenance)

Implement `cryptotrace update` command:

- GPG-verified pull from official GitHub signatures repository
- **Signature provenance tracking:** Every signature entry tracks:
```yaml
provenance:
  contributor: "github_username"
  review_status: "approved"    # pending | approved | deprecated
  review_date: "2026-01-15"
  reviewer: "maintainer_username"
  origin_reference: "https://tools.ietf.org/html/rfc1952"
```
- GPG public key baked into binary
- Rollback: `cryptotrace update --rollback`
- Air-gap mode: `cryptotrace update --from-file <path>`
- Opt-in — no automatic checks

**Supply chain security:** Separate signature and engine repos with different maintainer teams. Dual GPG key signing.

**Deliverable:** `cryptotrace update` with GPG verification, rollback, air-gap import, and provenance metadata.

---

#### Phase 2 Exit Criteria

- [ ] Magic byte detection covers 100+ formats with hierarchical subtype inference
- [ ] ZIP-based subtypes (OOXML, APK, JAR, EPUB) correctly distinguished
- [ ] Compression detection identifies all 8 target formats
- [ ] File analyzer classifies supported file types with conflict resolution
- [ ] `cryptotrace update` GPG-verifies and installs signatures
- [ ] Signature provenance metadata tracked in registry
- [ ] Rollback and air-gap import work
- [ ] All Phase 1 tests passing (regression gate)

---

### Phase 3 — Advanced Detection & Confidence Engine (Weeks 5–7)

**Goal:** Production-grade confidence engine with probabilistic calibration, encryption heuristics, and explainable signal attribution.

---

#### Step 3.1 — Full Multi-Signal Confidence Engine

**Input signals and weights (empirically validated against 200+ sample corpus):**

| Signal | Weight | Notes |
|--------|--------|-------|
| Entropy score | 0.20 | CORRELATED — cap active |
| Byte distribution uniformity | 0.15 | Chi-square, only if n >= 5120 |
| Block alignment | 0.20 | Length mod common block sizes |
| Magic byte match | 0.25 | Highest weight |
| Length pattern | 0.10 | Match expected lengths |
| Character set purity | 0.10 | String-type inputs only |
| **Sliding-window variance** | **0.10** | Low = uniform, high = mixed content |

**Correlated signal cap:** entropy + byte distribution uniformity ≤ 0.35.

**Signal breakdown exposed in every output:**
```json
{
  "signals": {
    "entropy": 0.87,
    "byte_distribution": 0.92,
    "block_alignment": 1.0,
    "magic_bytes": 0.0,
    "length_pattern": 0.95,
    "charset_purity": 1.0,
    "window_variance": 0.98
  },
  "conflicting_signals": ["magic_bytes"],
  "primary_drivers": ["block_alignment", "charset_purity"]
}
```

**Deliverable:** `src/core/confidence.rs` with signal breakdown in `DetectionResult`.

---

#### Step 3.2 — Probabilistic Calibration (Platt Scaling)

*Heuristic confidence → true probability. This is what makes "94%" mean "94% probability."*

Implement calibration layer (`src/core/calibration.rs`):

- Collect heuristic confidence scores + ground-truth labels from the test corpus
- Fit a Platt scaling model (logistic regression on heuristic scores) or isotonic regression for non-linear mappings
- Apply calibration at inference time: `calibrated_confidence = platt_transform(heuristic_confidence)`
- Until calibration data is sufficient (1000+ samples per class), output `calibrated: false` with the heuristic score
- Once calibrated, output `calibrated: true` alongside the calibrated score
- Re-calibrate with each signature DB update or when new detection classes are added

```json
{
  "confidence": 0.94,
  "calibrated": true,
  "calibration_samples": 1247,
  "heuristic_raw": 0.97
}
```

**Deliverable:** `src/core/calibration.rs` with Platt scaling implementation. Calibration status exposed in all outputs.

---

#### Step 3.3 — Encryption Heuristics

Implement `src/core/encryption.rs`:

**AES:** Block alignment (16-byte multiple), entropy > 7.8, OpenSSL `Salted__` prefix, GCM nonce (usually 12 bytes, document variance).
**RSA:** PEM headers `-----BEGIN RSA PRIVATE KEY-----`, DER ASN.1 sequences, key length signatures.
**ChaCha20/Salsa20:** No block alignment, very high entropy, 12/24-byte nonce patterns. Max confidence 0.55. Always qualify as "possible."

**Deliverable:** `src/core/encryption.rs` with documented FP rates per heuristic.

---

#### Step 3.4 — Risk and Weakness Mapping (Configurable)

Implement `src/intelligence/risk.rs`:

- CVE mappings loaded from external `signatures/cve_map.yaml`
- Users override via `cryptotrace.toml` → `[risk.overrides]`

| Algorithm | Risk Level | Weakness | Replacement |
|-----------|-----------|---------|-------------|
| MD5 | CRITICAL | Collision vulnerable | bcrypt, Argon2id |
| SHA1 | HIGH | Collision attacks demonstrated | SHA256 |
| bcrypt (< cost 10) | MEDIUM | Insufficient work factor | bcrypt (≥ 12) |
| bcrypt (≥ 12) | LOW | Current best practice | — |
| Argon2id | LOW | Current state of the art | — |
| DES | CRITICAL | 56-bit key, brute-forced | AES-256 |
| AES-128 CBC (no auth) | **HIGH** (org-configurable) | Malleable | AES-256-GCM |
| AES-256 GCM | LOW | Current best practice | — |
| NTLM | CRITICAL | No salt, no KDF | bcrypt, Argon2id |

**Deliverable:** `src/intelligence/risk.rs` with external CVE mapping + user overrides.

---

#### Step 3.5 — Test Corpus Expansion

- Minimum 200 samples per class (not 20)
- Private corpus repository — public repo gets synthetic samples only
- Legal requirements: contribution agreements, no PII, controlled malware submission

Define accuracy metrics: precision, recall, FP rate, F1 per class. Publish in `docs/ACCURACY.md`.

**Adversarial corpus:** truncated headers, XOR-obfuscated magic bytes, misaligned blocks, mixed encodings.

**Deliverable:** `tests/accuracy/` benchmark suite. Adversarial test cases.

---

#### Phase 3 Exit Criteria

- [ ] Encryption heuristics detect AES (CBC + GCM), RSA with documented FP rates
- [ ] Multi-signal confidence engine with correlated cap + sliding-window variance signal
- [ ] Probabilistic calibration: Platt scaling implemented, `calibrated` flag exposed
- [ ] Signal breakdown exposed in all output formats
- [ ] Risk mapper configurable via `cryptotrace.toml`
- [ ] Accuracy: ≥ 95% precision hash, ≥ 90% encoding, < 5% FP plaintext (200+ sample set)
- [ ] Adversarial test corpus created

---

### Phase 4 — AI Intelligence Layer (Weeks 8–10)

**Goal:** AI narrative layer with pluggable providers, structured constrained generation, and per-field hallucination detection. All features disabled by default.

---

#### Step 4.1 — Provider Abstraction (Async + Error-Handled)

Implement `src/providers/`:

- `mod.rs` — `#[async_trait] pub trait AiProvider` with `async fn complete()`
- `openai.rs` — GPT-4o family, GPT-4-turbo family, GPT-3.5-turbo family
- `anthropic.rs` — Claude Sonnet family, Claude Haiku family
- `ollama.rs` — Any locally served model

**Error handling:**
- Timeouts: retry once with backoff, then skip AI narrative
- HTTP 429: respect `Retry-After`, skip
- HTTP 401: clear error message about invalid API key
- Content policy violation: log, return without narrative
- Provider unavailable: "AI narrative unavailable — provider offline"

**Deliverable:** `src/providers/` with all three implementations.

---

#### Step 4.2 — Structured Constrained Generation + Hallucination Detection

Implement `src/intelligence/prompt.rs`:

- System prompt enforces JSON schema output (see Section 4 for full prompt)
- Response validator verifies each field independently:
  - `summary` — word count, markdown stripped
  - `risk_reason` — algorithm names cross-referenced against detection result
  - `recommended_action` — references only known algorithm names
  - `confidence_statement` — cited confidence matches actual value
- If ANY field contains an algorithm name NOT in the `DetectionResult`, discard ENTIRE response, log structured alert with field name, return "AI narrative unavailable — generation failed quality check"

**This replaces freeform narrative entirely.** No raw text accepted from AI.

**Deliverable:** `src/intelligence/prompt.rs` with JSON schema validation and per-field hallucination checking.

---

#### Step 4.3 — Community Provider Registry

`cryptotrace.providers.json` with security review requirement (2 maintainer approvals).

**Deliverable:** Registry file + contribution guide.

---

#### Phase 4 Exit Criteria

- [ ] `cryptotrace analyze --ai` produces structured JSON narrative (or clear error)
- [ ] Ollama works air-gapped with pre-downloaded model
- [ ] OpenAI/Anthropic work with API key config
- [ ] Hallucination detection catches fabricated algorithm names in ALL four fields
- [ ] AI output caching works (same SHA256 → cached)
- [ ] All error conditions handled gracefully (no crashes)
- [ ] All AI features disabled by default
- [ ] Community provider registry with security review policy

---

### Phase 5 — Recursive Layer Analyzer (Weeks 11–12)

**Goal:** Safe recursive unwrapping with depth limits, timeouts, compression bomb defense, and parser isolation.

---

#### Step 5.1 — Recursive Analyzer Core

Implement `src/analyzers/recursive.rs`:

- `MAX_RECURSION_DEPTH = 10` (configurable)
- `MAX_RECURSION_TIME_SECONDS = 30` (configurable)
- `MAX_EXPANSION_RATIO = 100` (default) — if decompressed size > 100x original, abort extraction with "Compression bomb detected"
- Cycle detection: SHA256 hash of each intermediate result (32 bytes per level). Abort on repeat.
- **Memory-safe byte handling:** Layer struct does NOT retain `decoded_bytes` after parent analysis completes. Stream and discard.
- Each recursion level passes through Input Sanitization Layer
- Build `LayerTree` (tree structure, supports branching)

```rust
#[derive(Debug, Serialize)]
pub struct Layer {
    pub depth: usize,
    pub detected_type: String,
    pub algorithm: String,
    pub confidence: f64,
    pub decoded_preview: Option<Vec<u8>>,  // Max 64 bytes
    pub decoded_length: usize,
    pub expansion_ratio: Option<f64>,       // ← tracked for compression bomb detection
    pub children: Vec<Layer>,
}
```

**Deliverable:** `src/analyzers/recursive.rs` with depth, timeout, ratio limits, cycle detection.

---

#### Step 5.2 — Parser Isolation (Subprocess Workers)

Implement `src/workers.rs`:

- Risky parsing operations (decompression, `libmagic`, ASN.1, image codecs) execute in isolated subprocess workers
- Worker protocol: stdin/stdout JSON communication with strict timeout (default: 10s per operation)
- Worker crashes do NOT affect the main process — log crash, mark signal as `unavailable`, continue analysis
- Worker pool: configurable max concurrent workers (default: 4)

**Why subprocess isolation matters:** A maliciously crafted ZIP bomb or ASN.1 payload that exploits a parser vulnerability crashes only the worker, not the analysis pipeline.

```rust
pub struct WorkerConfig {
    pub max_workers: usize,           // default: 4
    pub per_worker_timeout: Duration, // default: 10s
    pub worker_binary_path: PathBuf,  // path to cryptotrace-worker binary
}
```

**Deliverable:** `src/workers.rs` with isolated subprocess manager. Worker binary in separate `src/bin/worker.rs`.

---

#### Step 5.3 — Layer Tree Output

Update Report Generator for full layer tree output.

**Deliverable:** Layer tree in CLI, JSON, HTML formats. Decoded content only at deepest layer, truncated to 64 bytes.

---

#### Phase 5 Exit Criteria

- [ ] Recursive analyzer unwraps Base64 → GZIP → encrypted blob
- [ ] Depth limit of 10 enforced
- [ ] Timeout of 30s enforced
- [ ] MAX_EXPANSION_RATIO=100:1 enforced — compression bombs detected and aborted
- [ ] Cycle detection aborts on self-referential inputs
- [ ] Memory stable: 10-layer chain of 50MB inputs < 1GB RAM
- [ ] Parser isolation: worker crash does NOT crash main process
- [ ] Layer tree displayed in CLI, JSON, HTML
- [ ] All Phase 1-4 tests passing

---

### Phase 6 — API, Explainability & Format Inference (Weeks 13–14)

**Goal:** Production-grade REST API with async job architecture, complete signal attribution, and hierarchical format inference.

---

#### Step 6.1 — Async Job API

Replace synchronous `POST /analyze` with async job pattern:

```
POST   /v1/jobs              → Submit analysis, returns {job_id, status_url}
GET    /v1/jobs/:id          → Poll result (200 = done, 202 = in progress)
GET    /v1/jobs/:id/status   → Lightweight status check
DELETE /v1/jobs/:id          → Cancel running job
GET    /v1/health            → Health check (no auth)
GET    /v1/version           → Versions (no auth)
```

**Why async:** Recursive analysis of large files can take minutes. Synchronous HTTP timeouts or connection drops would lose results.

**Design:**
- In-memory job queue with configurable max concurrent (default: 4)
- Job results persisted to `~/.cryptotrace/jobs/` for durability
- Job TTL: 24 hours after completion, then auto-cleanup
- Auth: API key on all POST/DELETE endpoints

**Deliverable:** `src/api/jobs.rs` with `POST/GET/DELETE /v1/jobs/` endpoints.

---

#### Step 6.2 — Hierarchical Format Inference (Production)

Full implementation of the subtype detection framework from Phase 2.1:

- ZIP → inspect central directory → classify as OOXML / APK / JAR / EPUB / plain ZIP
- GPG → inspect packet tags → classify as armored / binary / key / signature
- PDF → inspect header + cross-reference table → classify version
- PE → inspect subsystem field → classify as EXE / DLL / SYS / DRV

**Deliverable:** Hierarchical format inference for all major overlapping-magic-byte format families.

---

#### Step 6.3 — Complete Explainability

Signal breakdown is already exposed from Phase 3. This step adds:

- **Conflicting signal documentation** in output: why did `magic_bytes` disagree with `entropy`?
- **Decision trace:** brief human-readable explanation of how the final confidence was computed
- **Calibration curve reference:** for calibrated models, include reference to the calibration dataset size and date

```json
{
  "signals": { ... },
  "primary_drivers": ["block_alignment", "charset_purity"],
  "conflicting_signals": ["magic_bytes"],
  "decision_trace": "Block alignment (1.0) and charset purity (1.0) strongly indicate hex-encoded SHA256. Magic byte match (0.0) expected — SHA256 has no magic bytes. Confidence weighted toward positive signals.",
  "calibrated": true,
  "calibration_info": {
    "dataset_size": 1247,
    "calibration_date": "2026-03-15",
    "method": "platt_scaling"
  }
}
```

**Deliverable:** Decision trace + calibration info in all `DetectionResult` outputs.

---

#### Phase 6 Exit Criteria

- [ ] Async job API: POST creates job, GET polls status, DELETE cancels
- [ ] Job results persisted to disk, survive process restart
- [ ] Hierarchical format inference for all overlapping magic-byte families
- [ ] Decision trace exposed in all output formats
- [ ] Calibration metadata exposed in output
- [ ] API key auth enforced on all POST/DELETE endpoints
- [ ] Rate limiting functional
- [ ] OpenAPI docs at `GET /docs`

---

### Phase 7 — Ecosystem & Open Source Launch (Weeks 15–16)

**Goal:** Secure, legal, production-ready public launch.

---

#### Step 7.1 — Legal and Security Foundation

- [ ] Trademark search for "CryptoTrace" — have backup name ready
- [ ] Finalize LICENSE (Apache 2.0 engine, CDLA signatures)
- [ ] SECURITY.md with disclosure policy (48h response, 90-day embargo)
- [ ] CODE_OF_CONDUCT.md
- [ ] CONTRIBUTING.md with DCO requirement
- [ ] Legal review: export controls (BIS/EAR), computer misuse laws, GDPR
- [ ] Publish data policy: NO telemetry, NO phone-home by default

---

#### Step 7.2 — Documentation

`GETTING_STARTED.md`, `CLI_REFERENCE.md`, `API_REFERENCE.md`, `ACCURACY.md`, `AIR_GAP_GUIDE.md`, `SIGNAL_ATTRIBUTION.md`, `CONFIGURATION.md`, `CONTRIBUTING.md`

---

#### Step 7.3 — Threat Intelligence Integrations (Opt-In)

- `integrations/virustotal.rs` — NOT air-gap compatible, requires API key
- `integrations/yara.rs` — YARA rule generation from detection results
- `integrations/siem.rs` — CEF/LEEF formatted logs

---

#### Step 7.4 — IDE Extensions (Stretch)

- VSCode extension (separate repo), uses REST API
- Browser extension (DevTools), user-initiated API calls only

---

## 7. Module Specifications

### DetectionResult Schema (Canonical)

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionResult {
    pub input_hash: String,                    // SHA256 as lowercase hex
    pub source_type: SourceType,               // "file" | "string" | "binary"
    pub entropy: f64,                          // 0.0 – 8.0
    pub sliding_entropy: Option<SlidingEntropy>,  // window analysis
    pub detected_type: String,                 // "hash" | "encoding" | "encryption" | ...
    pub algorithm: Option<String>,
    pub confidence: f64,                       // 0.0 – 1.0
    pub calibrated: bool,                      // true if Platt scaling applied
    pub calibration_samples: Option<usize>,    // dataset size for calibration
    pub heuristic_raw: Option<f64>,            // raw heuristic score before calibration
    pub confidence_is_provisional: bool,       // true for Phase 1 engine
    pub false_positive_risk: f64,
    pub risk_level: RiskLevel,                 // LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN
    pub weakness: Option<String>,
    pub weakness_cve: Vec<String>,
    pub recommendations: Vec<String>,
    pub signals: SignalBreakdown,              // ← raw signal values
    pub primary_drivers: Vec<String>,           // ← which signals drove the decision
    pub conflicting_signals: Vec<String>,       // ← signals that disagreed
    pub decision_trace: Option<String>,         // ← human-readable explanation
    pub layers: Vec<DetectionResult>,
    pub ai_narrative: Option<AiNarrative>,      // ← structured JSON, not freeform text
    pub detection_context: DetectionContext,    // "malware" | "password" | "forensics"
    pub engine_version: String,
    pub signature_db_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlidingEntropy {
    pub window_size_bytes: usize,       // 4096
    pub window_stride_bytes: usize,    // 2048
    pub window_scores: Vec<f64>,       // per-window entropy values
    pub max_window_entropy: f64,
    pub entropy_variance: f64,
    pub embedded_regions: Vec<OffsetRange>,  // high-entropy embedded payloads
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalBreakdown {
    pub entropy: f64,
    pub byte_distribution: Option<f64>,  // None if n < 5120
    pub block_alignment: f64,
    pub magic_bytes: f64,
    pub length_pattern: f64,
    pub charset_purity: Option<f64>,     // None for binary inputs
    pub window_variance: Option<f64>,    // sliding-window entropy variance
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AiNarrative {
    pub summary: String,
    pub risk_reason: String,
    pub recommended_action: String,
    pub confidence_statement: String,
}
```

---

## 8. Detection Techniques Reference

### Hash Identification Decision Tree

```
Input string
    │
    ├─ Contains only [0-9a-fA-F]?
    │      ├─ Length 32 → MD5 or UUID (no dashes)
    │      │      ├─ UUID pattern check → UUID, confidence 0.70
    │      │      └─ Otherwise → MD5, confidence 0.95
    │      ├─ Length 40 → SHA1, confidence 0.95 (strip whitespace)
    │      ├─ Length 64 → SHA256, confidence 0.97
    │      └─ Length 128 → SHA512, confidence 0.97
    │
    ├─ $2a$/$2b$/$2y$? → bcrypt (confidence: 0.99)
    ├─ $argon2id$/$argon2i$? → Argon2 (confidence: 0.99)
    ├─ Length 32, uppercase hex → NTLM (0.85) or LM Hash
    └─ None → Not a hash
```

### Base64 Identification

1. Charset `[A-Za-z0-9+/=]` only
2. Length multiple of 4 (or valid without padding)
3. 0, 1, or 2 `=` padding chars
4. Decode succeeds
5. OpenSSL `Salted__` prefix

**Confidence:** computed score = charset(0.3) + padding(0.2) + decode(0.4) + openssl(0.1)

### Encryption Confidence

High entropy alone is NEVER sufficient. Required:
- Entropy > 7.5 **AND**
- Chi-square pass (only if n >= 5120) **AND**
- At least one of: block alignment, known prefix, key size consistency

Without all three: "high entropy — possible encryption or compression" at confidence ≤ 0.65.

---

## 9. Prompt Engineering Design

See Section 4 for the full prompt design. Key principles:

- System prompt enforces structured JSON output (4 fields: summary, risk_reason, recommended_action, confidence_statement)
- Per-field validation: cross-reference every algorithm name against the input DetectionResult
- If ANY field contains fabricated content → discard entire response, log structured alert
- Input validation filter: scan DetectionResult JSON for prompt injection patterns before sending
- Temperature: 0.1 (configurable)
- Max tokens: 512 (configurable)

---

## 10. Testing & Validation Strategy

### Test Pyramid

```
         ┌──────────────────┐
         │   Accuracy      │  ← Precision/recall/F1 vs ground truth
         │   Benchmarks    │  ← Nightly, results published
         │   Adversarial   │  ← Red-teaming test cases
         │   Fuzz          │  ← 1M+ iterations full pipeline
         ├──────────────────┤
         │ Integration     │  ← End-to-end: input → JSON output
         ├──────────────────┤
         │  Unit Tests     │  ← Every detection function, every edge case
         │  Property Tests │  ← proptest-driven fuzz per module
         │  Security       │  ← Sanitization bypass, prompt injection
         └──────────────────┘
```

### Fuzz Testing

- Per-module: `proptest` for 10,000+ iterations
- Full pipeline: 1M+ random byte inputs, any crash = release blocker
- Every crash becomes a permanent regression test
- Runs nightly in CI

### Accuracy Gates (Hard Release Blockers)

- Hash precision ≥ 95%
- Encoding precision ≥ 90%
- FP rate on 200+ plaintext samples < 5%
- Recursive analyzer: 0 crashes on 1M+ fuzz corpus
- UUID vs MD5 FP rate < 1%
- All security tests pass
- Calibration: Platt scaling implemented (even if not yet fully trained)

---

## 11. Open Source Strategy

### Licensing

- **Engine code:** Apache 2.0
- **Signatures:** Community Data License Agreement — CDLA-Permissive-2.0
- **Samples:** Restricted — testing only, not redistributable independently
- **Documentation:** Creative Commons Attribution 4.0

### Legal Foundation

- **DCO:** All commits signed off. No CLAs.
- **Security policy:** PGP key in SECURITY.md, 48h response, 90-day embargo
- **Trademark:** Search before launch. Backup name ready.
- **Export controls:** Legal review before launch

### Governance

- **Launch:** Benevolent dictator model
- **6 months post-launch:** Governance board (3-5 members)
- **Signature reviews:** 2 maintainer approvals
- **Provider reviews:** Security review required
- **Dispute resolution:** Board majority vote, public record

### Positioning

*"The open-source Shazam for cryptography."*

### Success Metrics

| Metric | Target |
|--------|--------|
| GitHub stars | 5000+ in 12 months |
| External signature contributors | 20+ |
| Provider entries | 15+ |
| Monthly active users | 1000+ (opt-in telemetry, disabled by default) |
| Issues closed within 30 days | 90%+ |

---

## 12. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| False positives erode user trust | HIGH | HIGH | Publish accuracy benchmarks; expose `false_positive_risk`; document known FP cases |
| Crafted inputs crash recursive analyzer | MEDIUM | HIGH | Depth limit + timeout + expansion ratio + cycle detection + memory-safe byte handling + fuzz testing |
| AI provider API key exposure | MEDIUM | HIGH | Keys in config, never in code; `.gitignore`; `detect-secrets` pre-commit; config show redacts secrets |
| Detection evasion by adversary | HIGH | MEDIUM | Document limitations; publish known evasion techniques not detected |
| Entropy cannot distinguish AES vs Zstd | HIGH | MEDIUM | Multi-signal engine + correlated cap + sliding-window variance; document limitation |
| ML/calibration model overfits | MEDIUM | MEDIUM | Platt scaling with cross-validation; 200+ sample corpus; adversarial test set |
| Signature database becomes stale | MEDIUM | HIGH | GPG-signed updates + rollback + community contributions + dual-repo supply chain security |
| Supply chain attack via update | MEDIUM | CRITICAL | GPG-signed bundles; dual-repo; dual-GPG-key signing; key baked into binary |
| Compression bombs bypass limits | MEDIUM | HIGH | MAX_EXPANSION_RATIO=100:1; per-decompression memory limit (256MB); timeout (5s); parser isolation |
| Parser exploit via malicious input | MEDIUM | HIGH | Subprocess worker isolation; crash does not affect main process |
| AI hallucination bypasses regex filter | MEDIUM | HIGH | Structured constrained generation (JSON schema); per-field validation; discard on any mismatch |
| Hierarchical format inference incorrect | MEDIUM | MEDIUM | All subtype classifiers tested against labeled corpus; fall back to generic parent type on uncertainty |
| Cross-platform compatibility | MEDIUM | MEDIUM | Rust's cross-compilation + CI test matrix (Windows, macOS, Linux) |
| GDPR / data privacy | MEDIUM | HIGH | No telemetry by default; AI opt-in; sample corpus PII prohibition; data flow docs |
| Memory exhaustion from large files | MEDIUM | HIGH | Sanitization size limits (50MB); streaming byte handling; no decoded byte retention in recursion |

---

## Appendix A: Operational Security Checklist

Before each release:

- [ ] No secrets or API keys in code, comments, or git history
- [ ] `.gitignore` covers all secrets patterns
- [ ] GPG signatures verified for all updated signature files
- [ ] Fuzz testing (1M+ iterations, 0 crashes)
- [ ] All accuracy gates pass (≥ 95% precision hash, < 5% FP plaintext)
- [ ] AI features disabled by default — verified in clean install test
- [ ] Air-gap mode verified (no network requests during normal operation)
- [ ] REST API auth enforced — verified by curl without API key
- [ ] Cross-platform tests pass (Windows, macOS, Linux)
- [ ] Parser isolation verified — worker crash does not crash main process
- [ ] Compression bomb detection verified — 100:1 expansion ratio enforced

## Appendix B: Document Version History

| Version | Date | Changes |
|---------|------|---------|
| 3.0 | 2026-05-17 | Full Rust rewrite. Removed all Python. Added: sliding-window entropy, probabilistic calibration (Platt scaling), structured AI generation (per-field validation), hierarchical format inference (ZIP subtypes), MAX_EXPANSION_RATIO compression bomb defense, subprocess parser isolation, async job API, explainable signal attribution, signature provenance tracking. Phases restructured to 7 phases over 16 weeks. |

---

*This document is the canonical implementation plan for CryptoTrace v3.0.*
*Language: Rust (100%). All phases, steps, and exit criteria defined here supersede previous versions.*
*Last updated: Version 3.0 — Rust-native, architecturally complete — All 7 phases implemented.*
