.PHONY: all build test lint fmt clean release bench doc fuzz help

all: build

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clean:
	cargo clean

bench:
	cargo bench

doc:
	cargo doc --no-deps

fuzz:
	cargo +nightly fuzz run analyze -- -runs=10000

fuzz-long:
	cargo +nightly fuzz run analyze -- -runs=1000000

run:
	cargo run -- analyze

help:
	@echo "Targets:"
	@echo "  build        Build debug"
	@echo "  release      Build release (LTO, stripped)"
	@echo "  test         Run all tests"
	@echo "  lint         Run clippy"
	@echo "  fmt          Format code"
	@echo "  fmt-check    Check formatting"
	@echo "  clean        Clean build artifacts"
	@echo "  bench        Run benchmarks"
	@echo "  doc          Build documentation"
	@echo "  fuzz         Run fuzzer (30s)"
	@echo "  run          Quick analysis test"
