#!/usr/bin/env bash
set -euo pipefail

# CryptoTrace signature update script
# Downloads the latest signature database from the official repository.

REPO_URL="${1:-https://raw.githubusercontent.com/cryptotrace/signatures/main}"
SIG_DIR="signatures"
BACKUP_DIR="${SIG_DIR}/backup"

echo "==> Backing up current signatures"
mkdir -p "${BACKUP_DIR}"
cp "${SIG_DIR}/default.yaml" "${BACKUP_DIR}/default.yaml.$(date +%Y%m%d%H%M%S)"

echo "==> Downloading latest signature database"
curl -sfL "${REPO_URL}/default.yaml" -o "${SIG_DIR}/default.yaml.new"
curl -sfL "${REPO_URL}/default.yaml.sig" -o "${SIG_DIR}/default.yaml.sig" || true

if [ -f "${SIG_DIR}/default.yaml.sig" ]; then
    echo "==> Verifying GPG signature"
    gpg --verify "${SIG_DIR}/default.yaml.sig" "${SIG_DIR}/default.yaml.new" || {
        echo "WARNING: GPG verification failed"
        echo "The signature may be invalid. Proceed with caution."
    }
fi

mv "${SIG_DIR}/default.yaml.new" "${SIG_DIR}/default.yaml"
echo "==> Signature database updated successfully"

# Show version
grep '^version:' "${SIG_DIR}/default.yaml" || echo "Version field not found"
