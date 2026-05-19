# Contributing to CryptoTrace

Thank you for your interest in contributing to CryptoTrace! We welcome contributions of all kinds, including new detection signatures, bug fixes, documentation improvements, and feature proposals.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Workflow](#development-workflow)
4. [Adding Signatures](#adding-signatures)
5. [Adding Detection Algorithms](#adding-detection-algorithms)
6. [Testing Requirements](#testing-requirements)
7. [Commit Guidelines](#commit-guidelines)
8. [Pull Request Process](#pull-request-process)
9. [Community Providers](#community-providers)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository and clone your fork.
2. Ensure you have Rust 1.85+ (edition 2024) installed.
3. Build: `cargo build`
4. Test: `cargo test`
5. Create a branch for your work: `git checkout -b my-feature`

## Development Workflow

1. Make your changes in a feature branch.
2. Add or update tests as needed.
3. Run `cargo test` and `cargo clippy` to verify correctness and style.
4. Run the accuracy test suites for any affected detection modules:
   - `cargo test --test hash_accuracy`
   - `cargo test --test encoding_accuracy`
   - `cargo test --test compression_accuracy`
5. Submit a pull request.

## Adding Signatures

Signature entries are defined in `signatures/default.yaml`. Each entry requires:

```yaml
- id: unique-identifier
  name: Human-Readable Name
  magic_bytes: "HEXBYTES"     # Hex-encoded magic bytes
  offset: 0                    # Byte offset (0-based)
  category: file-type          # e.g., document, image, archive
  risk_level: LOW              # LOW, MEDIUM, HIGH, CRITICAL
  description: "Optional description of what this signature detects"
```

Guidelines:
- Magic bytes must be at least 2 bytes (4 hex chars).
- Use unique, descriptive IDs.
- Keep categories consistent with existing entries.
- Risk levels should reflect the security implication of the format.

## Adding Detection Algorithms

New detection algorithms (hash, encoding, encryption) should be added to the appropriate module under `src/core/`:

1. Implement the detection function in the relevant module (e.g., `hashing.rs`, `encoding.rs`).
2. Add a test for both positive and negative cases.
3. Follow the existing signal-based pattern: return confidence scores and supporting evidence.
4. Register the new algorithm in the detection pipeline in `file.rs`.

For format-level detection (file types, compression), add magic byte entries to `signatures/default.yaml` and detection logic to `src/format/mod.rs`.

## Testing Requirements

- Every new function must have unit tests.
- Changes to detection heuristics require updates to the accuracy test suites in `tests/`.
- False positive rates should not increase beyond existing benchmarks.
- Run `cargo test` before submitting. All tests must pass.

## Commit Guidelines

- Use conventional commit messages: `type(scope): description`
- Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`
- Example: `feat(hashing): add SHA-512/256 detection`
- Keep commits focused on a single logical change.

## Pull Request Process

1. Ensure all tests pass and your branch is up to date with main.
2. Update documentation if your change affects the public API or CLI.
3. Add a changelog entry if applicable.
4. Request review from a maintainer.
5. Address all review feedback before merge.

## Community Providers

If you maintain a collection of signatures relevant to the community, consider creating a community provider. See `docs/community-providers.json` for the registry format. Submit a pull request to add your provider to the registry.

Providers are categorized by trust level:
- **verified**: Reviewed and maintained by the CryptoTrace team.
- **community**: Maintained by third parties; reviewed for format compliance.
- **experimental**: New or unverified; use at your own risk.
