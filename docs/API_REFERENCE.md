# API Reference

## Overview

CryptoTrace provides a REST API for remote analysis. The API server is disabled by default — enable it in `cryptotrace.toml`:

```toml
[api]
enabled = true
bind = "127.0.0.1:8080"
api_key = "your-secret-key"  # optional
rate_limit = 60              # requests per minute
jobs_enabled = true          # enable async job queue
max_concurrent_jobs = 4
```

## Authentication

If an API key is configured, include it in requests via:

- `Authorization: Bearer <key>` header
- `X-API-Key: <key>` header

Requests without a valid key receive a `401 Unauthorized` response.

## Endpoints

### `GET /health`

Health check. No authentication required.

**Response `200`:**

```json
{
  "status": "ok",
  "engine_version": "0.1.0",
  "signature_db_version": "1.0.0",
  "uptime_seconds": 3600
}
```

### `GET /version`

Version information. No authentication required.

**Response `200`:**

```json
{
  "engine": "0.1.0",
  "signature_db": "1.0.0"
}
```

### `GET /docs`

Returns the OpenAPI 3.0 specification document. No authentication required.

### `POST /analyze`

Run the detection pipeline synchronously.

**Request body:**

```json
{
  "input": "5f4dcc3b5aa765d61d8327deb882cf99",
  "input_type": "string",
  "context": "forensics",
  "deep": false,
  "ai": false,
  "sandbox": false
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `input` | string | (required) | Input string, file path, or base64-encoded data |
| `input_type` | string | `"string"` | How to interpret input: `"string"`, `"file"`, or `"base64"` |
| `context` | string | `"forensics"` | Detection context: `"forensics"`, `"malware"`, or `"password"` |
| `deep` | boolean | `false` | Enable recursive layer analysis |
| `ai` | boolean | `false` | Enable AI narrative (requires AI provider config) |
| `sandbox` | boolean | `false` | Run in sandboxed subprocess |

**Response `200`:** A `DetectionResult` object (see schema below).

**Errors:** `400 Bad Request`, `401 Unauthorized`, `429 Too Many Requests`

### `POST /v1/jobs`

Submit an analysis job for asynchronous processing.

**Request body:** Same as `POST /analyze`.

**Response `200`:**

```json
{
  "job_id": 1,
  "status": "pending",
  "endpoint": "/v1/jobs/1"
}
```

### `GET /v1/jobs/:id`

Poll a submitted job for status and results.

**Response `200` (pending):**

```json
{
  "job_id": 1,
  "status": "Pending",
  "created_at": "1716000000.000",
  "updated_at": "1716000000.000"
}
```

**Response `200` (completed):**

```json
{
  "job_id": 1,
  "status": "Completed",
  "created_at": "1716000000.000",
  "updated_at": "1716000010.000",
  "result": { ... }
}
```

### `DELETE /v1/jobs/:id`

Cancel or remove a job.

## DetectionResult Schema

```json
{
  "input_hash": "sha256-of-input",
  "source_type": "String",
  "entropy": 3.8,
  "sliding_entropy": null,
  "detected_type": "hash",
  "algorithm": "MD5",
  "confidence": 0.98,
  "calibrated": true,
  "calibration_samples": 500,
  "heuristic_raw": 0.95,
  "confidence_is_provisional": false,
  "false_positive_risk": 0.01,
  "risk_level": "Critical",
  "weakness": "collision_vulnerable",
  "weakness_cve": ["CVE-2013-4103"],
  "recommendations": ["Replace with bcrypt or Argon2id"],
  "signals": {
    "entropy": 0.9,
    "byte_distribution": 0.8,
    "block_alignment": 0.0,
    "magic_bytes": 0.0,
    "length_pattern": 1.0,
    "charset_purity": 1.0,
    "window_variance": 0.1
  },
  "primary_drivers": ["length_pattern", "charset_purity"],
  "conflicting_signals": ["magic_bytes"],
  "decision_trace": "String or null",
  "layers": [],
  "ai_narrative": null,
  "detection_context": "Forensics",
  "engine_version": "0.1.0",
  "signature_db_version": "1.0.0"
}
```

## Error Responses

```json
{
  "error": "bad_request",
  "message": "File not found: /nonexistent/file.txt"
}
```

| HTTP Status | Error Type | Description |
|-------------|------------|-------------|
| 400 | `bad_request` | Invalid input or parameters |
| 401 | `unauthorized` | Missing or invalid API key |
| 404 | `not_found` | Resource (e.g., job) not found |
| 429 | `rate_limited` | Too many requests; includes `retry_after_seconds` |
| 500 | `internal_error` | Server error |
