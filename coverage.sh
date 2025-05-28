#!/bin/bash

set -e

# Create coverage data folder
mkdir -p coverage/profraw
mkdir -p coverage/report
rm -f coverage/profraw/*.profraw

# Install tools
cargo install grcov --force
rustup component add llvm-tools-preview

# Clean old build and coverage artifacts
cargo clean
# Run clippy (optional, for linting)
cargo clippy --all-targets --message-format=human

# Set env vars for coverage with stable Rust
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage -Clink-dead-code -Coverflow-checks=off -Ccodegen-units=1"
export LLVM_PROFILE_FILE="coverage/profraw/sib-%p-%m.profraw"

# Run tests
cargo test

# Generate HTML coverage report
grcov . \
  --binary-path ./target/debug/ \
  -s ./src \
  -t html \
  --ignore-not-existing \
  -o coverage/report
