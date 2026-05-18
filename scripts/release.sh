#!/usr/bin/env bash
set -euo pipefail

# CryptoTrace release script
# Builds release binaries, runs tests, and creates archives.

VERSION="${1:-$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')}"
PROJECT="cryptotrace"
RELEASE_DIR="target/release"
STAGING_DIR="target/${PROJECT}-${VERSION}"

echo "==> Building release for ${PROJECT} v${VERSION}"
cargo build --release

echo "==> Running tests"
cargo test

echo "==> Staging files"
mkdir -p "${STAGING_DIR}"

# Copy binaries (platform-specific extension)
if [ "$(uname)" = "MINGW"* ] || [ "$(uname)" = "MSYS"* ]; then
    cp "${RELEASE_DIR}/${PROJECT}.exe" "${STAGING_DIR}/"
    cp "${RELEASE_DIR}/${PROJECT}-worker.exe" "${STAGING_DIR}/"
else
    cp "${RELEASE_DIR}/${PROJECT}" "${STAGING_DIR}/"
    cp "${RELEASE_DIR}/${PROJECT}-worker" "${STAGING_DIR}/"
fi

# Copy docs and config
cp README.md LICENSE SECURITY.md cryptotrace.toml.example "${STAGING_DIR}/"
cp -r signatures docs "${STAGING_DIR}/"

echo "==> Creating archive"
(cd target && tar czf "${PROJECT}-${VERSION}.tar.gz" "${PROJECT}-${VERSION}")
(cd target && zip -r "${PROJECT}-${VERSION}.zip" "${PROJECT}-${VERSION}")

echo "==> Done: target/${PROJECT}-${VERSION}.tar.gz"
echo "    SHA256: $(sha256sum "target/${PROJECT}-${VERSION}.tar.gz" | cut -d' ' -f1)"
