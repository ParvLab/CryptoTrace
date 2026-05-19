#!/usr/bin/env bash
set -euo pipefail

# CryptoTrace benchmark script
# Runs criterion benchmarks and displays results.

echo "==> Running benchmarks"
cargo bench

echo ""
echo "==> Benchmark results saved to target/criterion/"
echo "    Open target/criterion/report/index.html to view"
