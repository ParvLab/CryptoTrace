# CLI Reference

## Usage

```bash
cryptotrace [COMMAND] [OPTIONS]
```

## Global options

| Flag | Description |
|------|-------------|
| `-h`, `--help` | Print help information |
| `-V`, `--version` | Print version information |

## Commands

### `analyze`

Analyze a string or file for cryptographic fingerprints.

```bash
cryptotrace analyze [OPTIONS] <INPUT>
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `INPUT` | String literal or file path to analyze |

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--context <CONTEXT>` | Threat context: `forensics`, `malware`, or `password` | `forensics` |
| `--deep` | Enable recursive layer analysis | `false` |
| `--json` | Output raw JSON instead of formatted report | `false` |
| `--explain` | Show full signal breakdown and decision trace | `false` |
| `--ai` | Append AI narrative (requires AI provider config) | `false` |
| `--sandbox` | Run analysis in sandboxed subprocess | `false` |

**Examples:**

```bash
# Basic hash detection
cryptotrace analyze "5f4dcc3b5aa765d61d8327deb882cf99"

# File analysis with malware context
cryptotrace analyze suspicious.exe --context malware

# Recursive unwrapping with JSON output
cryptotrace analyze layered-data.bin --deep --json

# Full explainability
cryptotrace analyze unknown-hash.txt --explain

# With AI narrative
cryptotrace analyze payload.bin --ai
```

### `update`

Update the signature database.

```bash
cryptotrace update [OPTIONS]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--rollback` | Roll back to the previous signature database version |
| `--from-file <PATH>` | Import signature update from a local file (air-gap mode) |
| `--verify <PATH>` | Path to detached Ed25519 or GPG signature for verification |

**Examples:**

```bash
# Check current version
cryptotrace update

# Rollback
cryptotrace update --rollback

# Import from file with signature verification
cryptotrace update --from-file new-signatures.yaml --verify new-signatures.yaml.sig
```

### `version`

Show engine and signature database versions.

```bash
cryptotrace version
```

### `cache`

Manage caches.

```bash
cryptotrace cache <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `clear` | Clear the AI output cache |

### `config`

Manage configuration.

```bash
cryptotrace config <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `show` | Show active configuration (secrets redacted) |

### `calibrate`

Train or manage the calibration model.

```bash
cryptotrace calibrate <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `train` | Train a new calibration model from CSV data |
| `generate` | Generate synthetic training data |
| `status` | Show current calibration model info |

**`train` options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--data <PATH>` | Path to CSV training dataset | `calibration_data/train.csv` |
| `--output <PATH>` | Path to save the trained model | `calibration_data/model.json` |
| `--learning-rate <FLOAT>` | Gradient descent learning rate | `0.1` |
| `--epochs <INT>` | Number of training epochs | `1000` |
| `--l2-lambda <FLOAT>` | L2 regularization strength | `0.001` |

**`generate` options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--samples <INT>` | Number of samples per class | `200` |
| `--output <PATH>` | Output CSV path | `calibration_data/train.csv` |
