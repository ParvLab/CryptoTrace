# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Active development |

## Reporting a Vulnerability

If you discover a security vulnerability in CryptoTrace, **do not** open a public GitHub issue. Please report it privately.

### Contact

Send an encrypted email to **security@cryptotrace.dev** using our PGP key:

```
Fingerprint: 3A4B 5C6D 7E8F 9A0B 1C2D 3E4F 5A6B 7C8D 9E0F 1A2B
```

If you do not have PGP set up, you may report via the private vulnerability reporting mechanism on GitHub (if enabled for this repository).

### Response SLA

- **48 hours:** Initial acknowledgement of receipt
- **7 days:** Triage and severity assessment with expected fix timeline
- **90 days:** Standard embargo period from disclosure to public fix
  - Extensions may be granted for complex vulnerabilities

### What to include

- Affected version(s) and platform(s)
- Description of the vulnerability and impact
- Steps to reproduce (PoC preferred but not required)
- Any suggested mitigation or fix

## Scope

The following are in scope for security reports:

- CryptoTrace engine (Rust binaries)
- Signature database loading and parsing
- Input sanitization and sandboxing
- REST API authentication and rate limiting
- AI provider integration and prompt handling
- Update mechanism and signature verification

The following are **out of scope**:

- Third-party AI provider infrastructure (OpenAI, Anthropic, Ollama)
- Operating system vulnerabilities
- Social engineering of project maintainers

## Security Design

### Sandboxing

Risky parsing operations (decompression, binary parsing) run in isolated subprocesses via:

- **Windows:** Job Objects with process group kill on timeout
- **Linux:** Seccomp-bpf with restricted syscall whitelist
- **macOS:** sandbox-exec with minimal entitlements

If a worker process crashes or is compromised, the main analysis pipeline remains unaffected.

### Input Limits

| Limit | Value |
|-------|-------|
| Maximum file size | 50 MB |
| Maximum string input | 10 MB |
| Maximum recursion depth | 10 layers |
| Maximum recursion time | 30 seconds |
| Maximum expansion ratio | 100:1 |
| Per-decompression memory | 256 MB |

### No Network by Default

All cloud/AI features are opt-in. The engine operates fully air-gapped with no network calls unless explicitly configured. This is verified by:

- No HTTP client initialized at startup
- No DNS resolution attempted during normal operation
- All network features gated behind explicit configuration flags
- Network calls logged at `info` level for auditability

### AI Safety

- Structured output only (no freeform text generation)
- Per-field JSON validation prevents hallucination
- All AI output flagged as non-authoritative
- Prompt injection defense: AI never receives raw user input, only structured `DetectionResult` JSON
- Temperature set to 0.1 (configurable) to reduce injection success rate

### Supply Chain Security

- Signature database updates verified via Ed25519 signatures (primary) or GPG (fallback)
- Dual-repo architecture: engine and signature sources are independently maintained
- Provenance log tracks every update with timestamp and fingerprint
- Rollback capability: `cryptotrace update --rollback`
- Air-gap import: `cryptotrace update --from-file <path> --verify <sig>`

### Configuration Security

- API keys stored in config file or environment variables, never in code
- `cryptotrace config show` redacts all secrets
- `.gitignore` covers all secret file patterns
- `detect-secrets` pre-commit hook recommended for contributors
