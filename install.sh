#!/usr/bin/env bash
set -euo pipefail

REPO="parv68/CryptoTrace"
VERSION="${1:-latest}"

if [ "$VERSION" = "latest" ]; then
  API_URL="https://api.github.com/repos/$REPO/releases/latest"
else
  API_URL="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
fi

echo "→ CryptoTrace Installer"
echo "  Repo: $REPO"
echo "  Version: $VERSION"
echo ""

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux)  TARGET="x86_64-unknown-linux-gnu" ;;
  darwin)
    if [ "$ARCH" = "arm64" ]; then
      TARGET="aarch64-apple-darwin"
    else
      TARGET="x86_64-apple-darwin"
    fi
    ;;
  *)
    echo "Error: Unsupported OS: $OS"
    exit 1
    ;;
esac

echo "→ Detected: $OS / $ARCH → $TARGET"
echo ""

# Fetch release data
echo "→ Fetching release info..."
RELEASE_JSON=$(curl -sSfL "$API_URL")
if [ -z "$RELEASE_JSON" ]; then
  echo "Error: Failed to fetch release info"
  exit 1
fi

RELEASE_TAG=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)",/\1/')
echo "  Release: $RELEASE_TAG"

# Find the asset URL
ARCHIVE_NAME="cryptotrace-${RELEASE_TAG}-${TARGET}.tar.gz"
ASSET_URL=$(echo "$RELEASE_JSON" | grep -o "https://[^\"]*${ARCHIVE_NAME}\"" | sed 's/"$//')

if [ -z "$ASSET_URL" ]; then
  echo "Error: Could not find asset for $TARGET in release $RELEASE_TAG"
  echo "  Expected: $ARCHIVE_NAME"
  exit 1
fi

echo "→ Downloading $ARCHIVE_NAME ..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
curl -sSfL "$ASSET_URL" -o "$TMP_DIR/archive.tar.gz"

echo "→ Extracting..."
tar xzf "$TMP_DIR/archive.tar.gz" -C "$TMP_DIR"

# Find the extracted directory
EXTRACTED_DIR=$(find "$TMP_DIR" -maxdepth 1 -type d | tail -1)

# Install to /usr/local/bin
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  echo "→ Need sudo to install to $INSTALL_DIR"
  sudo cp "$EXTRACTED_DIR/cryptotrace" "$INSTALL_DIR/"
  sudo cp "$EXTRACTED_DIR/cryptotrace-worker" "$INSTALL_DIR/"
else
  cp "$EXTRACTED_DIR/cryptotrace" "$INSTALL_DIR/"
  cp "$EXTRACTED_DIR/cryptotrace-worker" "$INSTALL_DIR/"
fi

# Install signatures + calibration data
DATA_DIR="/usr/local/share/cryptotrace"
echo "→ Installing data to $DATA_DIR"
if [ ! -w "/usr/local/share" ]; then
  sudo mkdir -p "$DATA_DIR"
  sudo cp -r "$EXTRACTED_DIR/signatures" "$DATA_DIR/"
  sudo cp -r "$EXTRACTED_DIR/calibration_data" "$DATA_DIR/"
else
  mkdir -p "$DATA_DIR"
  cp -r "$EXTRACTED_DIR/signatures" "$DATA_DIR/"
  cp -r "$EXTRACTED_DIR/calibration_data" "$DATA_DIR/"
fi

echo ""
echo "✓ CryptoTrace $RELEASE_TAG installed!"
echo "  Binary:       $INSTALL_DIR/cryptotrace"
echo "  Worker:       $INSTALL_DIR/cryptotrace-worker"
echo "  Data:         $DATA_DIR"
echo ""
echo "  Run: cryptotrace --help"
echo "  Run: cryptotrace analyze \"your-input\""
