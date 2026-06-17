# CryptoTrace Configuration Reference

CryptoTrace reads configuration from `cryptotrace.toml` in the current directory.
All keys have sensible defaults — the file is entirely optional.

## Global

```toml
# Enable AI narrative generation (disabled by default — must opt in)
# [ai]
# enabled = true

# Enable sandboxed analysis (disabled by default)
# [sandbox]
# enabled = true
```

## [ai] Section

Controls the optional AI narrative layer. All features are **disabled by default**.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Must be `true` to use `--ai` flag |
| `provider` | string | `"openai"` | One of: `openai`, `anthropic`, `local` |
| `model` | string | `"gpt-4o"` | Model name or family |
| `api_key` | string | — | API key (also settable via `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` env) |
| `base_url` | string | provider default | Custom endpoint (required for local/Ollama: `http://localhost:11434`) |
| `temperature` | float | `0.1` | LLM temperature (lower = more deterministic) |
| `max_tokens` | int | `512` | Maximum tokens in AI response |
| `timeout_seconds` | int | `30` | HTTP timeout for provider call |

```toml
[ai]
enabled = true
provider = "ollama"
model = "llama3"
base_url = "http://localhost:11434"
temperature = 0.1
```

## [ai.cache] Section

Controls AI narrative caching.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable narrative caching |
| `ttl_days` | int | `7` | Cache entry time-to-live |
| `max_entries` | int | `10000` | Maximum cache entries (LRU eviction) |

## [sandbox] Section

Controls subprocess isolation for untrusted input analysis.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable sandboxed analysis |
| `timeout_seconds` | int | `30` | Worker timeout before kill |
| `max_memory_mb` | int | `512` | Per-worker memory limit |
| `max_concurrent` | int | `4` | Max concurrent workers |

## [entropy] Section

Controls entropy classification thresholds.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `thresholds.plaintext_max` | float | `3.5` | Entropy below this = plaintext/structured |
| `thresholds.mixed_max` | float | `6.0` | Entropy below this = mixed/partially encoded |
| `thresholds.compressed_max` | float | `7.5` | Entropy below this = compressed/encoded |
| | | | Above `compressed_max` = high entropy |

## [risk] Section

Controls risk level overrides and CVE mapping.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `overrides` | table | `{}` | Algorithm → RiskLevel overrides |

```toml
[risk.overrides]
MD5 = "Low"
SHA1 = "Medium"
```

## Environment Variables

Variables override `cryptotrace.toml` values:

| Variable | Overrides |
|----------|-----------|
| `OPENAI_API_KEY` | AI provider key (OpenAI) |
| `ANTHROPIC_API_KEY` | AI provider key (Anthropic) |
| `AI_PROVIDER` | AI provider type |
| `AI_BASE_URL` | AI provider base URL |
| `AI_MODEL` | AI model name |
| `CRYPTOTRACE_MAX_MEMORY_MB` | Worker memory limit (sandbox) |

## File Locations

| Path | Purpose |
|------|---------|
| `cryptotrace.toml` | User configuration (per-directory) |
| `signatures/default.yaml` | Magic byte registry |
| `signatures/cve_map.yaml` | CVE-to-algorithm mapping |
| `calibration_data/model.json` | Trained Platt scaling model |
| `calibration_data/train.csv` | Training samples |
| `~/.cryptotrace/audit/` | Audit log files |
