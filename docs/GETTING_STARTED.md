# Getting Started with CryptoTrace

## Installation

### Prerequisites

- **Rust 1.85+** (stable toolchain)
- Supported OS: Windows, macOS, Linux

### Build from source

```bash
git clone https://github.com/cryptotrace/cryptotrace.git
cd cryptotrace
cargo build --release
```

The release binary will be at `target/release/cryptotrace` (~6 MB). A worker binary is also produced at `target/release/cryptotrace-worker` (~826 KB) for subprocess isolation.

### Verify installation

```bash
cryptotrace version
```

Expected output:
```
CryptoTrace v0.1.0
Engine: 0.1.0
Signature DB: 1.0.0
```

## Your first analysis

### Analyze a string

```bash
cryptotrace analyze "5f4dcc3b5aa765d61d8327deb882cf99"
```

This detects the string as an MD5 hash and displays:
- Entropy score
- Risk level (Critical for MD5)
- Confidence percentage
- Signal breakdown
- Weakness and CVE information
- Recommendation (e.g., "Replace with bcrypt or Argon2id")

### Analyze a file

```bash
cryptotrace analyze ~/Downloads/suspicious-file.bin --context malware
```

The `--context` flag adjusts detection sensitivity:
- `forensics` (default) — balanced detection
- `malware` — high false-positive tolerance, flags anything above LOW risk
- `password` — low false-positive tolerance, only flags HIGH/CRITICAL

### Output JSON

```bash
cryptotrace analyze "5f4dcc3b5aa765d61d8327deb882cf99" --json
```

## Key features

### Recursive analysis

Unwrap nested encoding/compression layers:

```bash
cryptotrace analyze encoded-file.bin --deep
```

### Explain mode

Show detailed signal attribution:

```bash
cryptotrace analyze "5f4dcc3b5aa765d61d8327deb882cf99" --explain
```

### AI narrative (opt-in)

Requires an AI provider configured in `cryptotrace.toml`:

```bash
cryptotrace analyze suspicious-file.bin --ai
```

### Configuration

Copy the example config and edit:

```bash
cp cryptotrace.toml.example cryptotrace.toml
```

## Next steps

- Read the [CLI Reference](CLI_REFERENCE.md) for all commands
- Read the [Air-Gap Guide](AIR_GAP_GUIDE.md) for offline deployment
- Read [Signal Attribution](SIGNAL_ATTRIBUTION.md) to understand confidence scoring
