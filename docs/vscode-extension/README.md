# CryptoTrace VSCode Extension

This directory contains the documentation and blueprint for the CryptoTrace VSCode extension, which brings cryptographic fingerprinting and threat detection directly into the editor.

## Features

### 1. Inline Detection Highlighting

When opening a file, the extension automatically runs CryptoTrace analysis and highlights:

- **Hash values**: MD5 (red), SHA1 (yellow), SHA256 (green), etc.
- **Encoded data**: Base64, Base58, Hex, URL encoding
- **Compressed data**: GZIP, Zstd, Brotli, LZ4, BZ2
- **Encryption artifacts**: RSA keys, AES/Salsa20/ChaCha20 heuristics
- **Credentials**: Passwords, API keys, NTLM hashes

Each highlight has a hover tooltip showing the detection details (algorithm, confidence, risk level).

### 2. File Explorer Decorations

File icons and badges in the Explorer view show detected cryptographic properties:

- 🔒 Encrypted files
- 📦 Compressed/archived files
- 🔑 Key material files
- 🧬 High-entropy binary files

### 3. Command Palette

| Command | Description |
|---------|-------------|
| `CryptoTrace: Analyze Selection` | Run detection on the current text selection |
| `CryptoTrace: Analyze File` | Run detection on the entire open file |
| `CryptoTrace: Show Report` | Open a rich HTML report panel |
| `CryptoTrace: Add to Allowlist` | Mark current selection as a known safe value |
| `CryptoTrace: Toggle Decoration` | Enable/disable inline highlighting |

### 4. Diagnostics Panel

A dedicated panel (View → Output → CryptoTrace) shows:

- Full detection results with signal breakdown
- Confidence scores and risk assessments
- CVE references for weak algorithms
- AI narrative (if configured)
- Deep layer analysis

### 5. Settings

```jsonc
{
  // Enable/disable the extension
  "cryptotrace.enabled": true,

  // Path to the cryptotrace CLI binary
  "cryptotrace.binaryPath": "cryptotrace",

  // Highlight style for each detection type
  "cryptotrace.highlightStyle": {
    "hash": { "color": "#ff0000", "background": "#ff000020" },
    "encoding": { "color": "#ffaa00", "background": "#ffaa0020" },
    "encryption": { "color": "#ff6600", "background": "#ff660020" },
    "compression": { "color": "#00aaff", "background": "#00aaff20" },
    "credential": { "color": "#ff00ff", "background": "#ff00ff20" }
  },

  // Enable AI narrative feature
  "cryptotrace.aiEnabled": false,

  // Path to cryptotrace config file
  "cryptotrace.configPath": ".cryptotrace.toml",

  // Threat intel integration
  "cryptotrace.vtApiKey": "",
  "cryptotrace.yaraRulesPath": ""
}
```

## Architecture

```
┌────────────────────────────────────────────────┐
│  VSCode Extension (TypeScript)                 │
│  ┌──────────────┐  ┌───────────────────────┐  │
│  │ Decoration   │  │ Command Palette       │  │
│  │ Provider     │  │ + Diagnostics Panel   │  │
│  └──────┬───────┘  └──────────┬────────────┘  │
│         │                     │               │
│         ▼                     ▼               │
│  ┌────────────────────────────────────────┐   │
│  │  CryptoTrace Language Server (LSP)     │   │
│  │  - Caches results per file             │   │
│  │  - Incremental analysis on edit        │   │
│  │  - Respects `.gitignore` patterns      │   │
│  └────────────────┬───────────────────────┘   │
│                   │                            │
│                   ▼                            │
│  ┌────────────────────────────────────────┐   │
│  │  CLI Bridge (spawns cryptotrace)       │   │
│  │  - Parses JSON output                  │   │
│  │  - Handles long-running analysis       │   │
│  └────────────────────────────────────────┘   │
└────────────────────────────────────────────────┘
```

## Development

### Prerequisites
- Node.js 18+
- VSCode 1.85+
- `cryptotrace` CLI in `$PATH`

### Setup
```bash
cd extensions/vscode
npm install
npm run compile
```

### Debug
Open the extension directory in VSCode and press `F5` to launch an Extension Development Host.

## Publishing

```bash
npm run package
vsce publish
```

See [VSCode Extension Marketplace](https://marketplace.visualstudio.com/) for publishing instructions.
