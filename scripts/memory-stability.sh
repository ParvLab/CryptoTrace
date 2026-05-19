#!/usr/bin/env bash
# Memory stability test: verifies deep recursive analysis stays under 1 GB RSS.
# Runs the test binary and monitors peak memory usage via /usr/bin/time -v.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Memory Stability Test ==="
echo "Building test binary..."
cargo test --test memory_stability --no-run 2>&1

TEST_BIN=$(find target/debug -name "memory_stability-*" -type f 2>/dev/null | head -1)
if [ -z "$TEST_BIN" ]; then
    echo "ERROR: could not find memory_stability test binary"
    exit 1
fi

echo "Running: $TEST_BIN"
echo "---"

if command -v /usr/bin/time &>/dev/null; then
    /usr/bin/time -v "$TEST_BIN" --nocapture 2>&1
else
    "$TEST_BIN" --nocapture
fi

# Additionally run with soft and hard RSS limits using ulimit for extra safety.
echo ""
echo "=== Running with 1 GB hard RSS limit ==="
ulimit -v 1048576 2>/dev/null  # 1 GB virtual memory
ulimit -m 1048576 2>/dev/null  # 1 GB RSS
if "$TEST_BIN" --nocapture; then
    echo "PASS: memory stayed within 1 GB limit"
else
    echo "FAIL: process exceeded 1 GB limit or crashed"
    exit 1
fi
