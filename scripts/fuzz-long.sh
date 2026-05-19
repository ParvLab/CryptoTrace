#!/usr/bin/env bash
# Long-running fuzz test: 1M iterations on the analyze fuzz target.
# Requires: nightly Rust toolchain, cargo-fuzz installed.
#
# Usage: bash scripts/fuzz-long.sh [optional corpus dir]
set -euo pipefail

CORPUS="${1:-fuzz/corpus/analyze}"
RUNTIME_SECS="${2:-3600}"   # default 1 hour wall-clock timeout

cd "$(dirname "$0")/.."

echo "=== CryptoTrace Fuzz: 1M iterations ==="
echo "Corpus: $CORPUS"
echo "Max runtime: ${RUNTIME_SECS}s"
echo ""

# Build fuzz target (release + asan)
cargo +nightly fuzz build
echo ""

# Run with iteration limit. If the process crashes, collect the artifact.
echo "Running..."
cargo +nightly fuzz run analyze -- \
    -artifact_prefix=fuzz/artifacts/analyze/ \
    -runs=1000000 \
    -max_total_time="$RUNTIME_SECS" \
    "$CORPUS"

EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "PASS: 1M iterations completed with no crashes."
else
    echo ""
    echo "FAIL: Fuzzer exited with code $EXIT_CODE"
    echo "Check fuzz/artifacts/analyze/ for crash inputs."
    exit $EXIT_CODE
fi
