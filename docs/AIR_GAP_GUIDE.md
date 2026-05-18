# Air-Gap Guide

CryptoTrace is designed to operate fully air-gapped with **no network calls** unless explicitly configured. This guide explains how to deploy and use CryptoTrace in an offline, air-gapped environment.

## Default State: Fully Offline

Out of the box, CryptoTrace makes **zero network calls**. All of the following are disabled by default:

- AI narrative generation
- Signature database updates (manual only)
- VirusTotal threat intelligence
- Community provider downloads
- REST API (also disabled by default)

## Verification Checklist

Use this checklist to confirm your deployment is truly air-gapped:

- [ ] `cryptotrace.toml` does not contain `[ai] enabled = true`
- [ ] `cryptotrace.toml` does not contain `[api] enabled = true`
- [ ] No `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `VT_API_KEY` environment variables set
- [ ] `cryptotrace analyze` on a test input completes within 1 second (no network timeout)
- [ ] Running with `--ai` flag returns an error (not a timeout)

### Verifying with network monitoring

```bash
# Linux (using nethogs or tcpdump)
sudo tcpdump -i any port not 22 2>/dev/null &
cryptotrace analyze "test string"
sudo pkill tcpdump
```

If any outbound connections appear during normal operation, this is a bug.

## Offline Signature Updates

### Method 1: USB transfer

On an internet-connected machine:

```bash
# Check for updates
cryptotrace update

# Export current signatures
cp signatures/default.yaml /media/usb/
```

On the air-gapped machine:

```bash
cryptotrace update --from-file /media/usb/default.yaml
```

### Method 2: Signed updates with verification

On an internet-connected machine:

```bash
# Download update and its signature
curl -O https://signatures.cryptotrace.dev/v1/default.yaml
curl -O https://signatures.cryptotrace.dev/v1/default.yaml.sig

# Transfer both files to air-gapped machine via USB
```

On the air-gapped machine:

```bash
# Import with signature verification
cryptotrace update --from-file default.yaml --verify default.yaml.sig
```

### Method 3: Manual signature file placement

Simply copy a signature YAML file to `signatures/default.yaml`:

```bash
cp /media/usb/custom-signatures.yaml signatures/default.yaml
```

## Offline AI Narratives

CryptoTrace supports fully offline AI narrative generation using local models (Ollama).

### Setup on internet-connected machine

1. Install Ollama
2. Download a model: `ollama pull llama3.2:3b`
3. Export the model: `ollama export llama3.2:3b > model.gguf`
4. Transfer `model.gguf` to air-gapped machine via USB

### Setup on air-gapped machine

1. Install Ollama
2. Import the model: `ollama import model.gguf`
3. Configure `cryptotrace.toml`:

```toml
[ai]
enabled = true
provider = "ollama"
model_family = "llama3.2"
base_url = "http://localhost:11434"
```

4. Verify: `cryptotrace analyze "test" --ai`

## Community Providers (Offline)

Community provider signatures can be downloaded on an internet-connected machine and transferred via USB:

```bash
# On internet-connected machine
cp -r signatures/community /media/usb/signatures/

# On air-gapped machine
cp -r /media/usb/signatures/community signatures/
```

## Threat Intelligence (Always Online)

The following features require network access and are **not air-gap compatible**:

- VirusTotal hash lookup (`intelligence::threat_intel::query_virustotal`)
- OpenAI/Anthropic AI providers (use Ollama instead)

These features report an error if no network is available, rather than hanging indefinitely.

## Troubleshooting

**Q: Analysis takes > 5 seconds — is it making network calls?**

Run with tracing enabled: `RUST_LOG=info cryptotrace analyze "test"`. Look for `Making request` or `Downloading` log messages. If none appear and the delay persists, check for DNS resolution attempts in your network monitor.

**Q: I need to verify no data leaves the machine.**

Use `strace` (Linux) or `Procmon` (Windows) to monitor file and network access during analysis. Any `connect()` syscall to a non-local address is a potential data leak.
