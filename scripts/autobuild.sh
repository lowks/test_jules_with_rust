#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "--- Starting Autobuild Script ---"

echo "Step 1: Checking code formatting..."
cargo fmt -- --check

echo "Step 2: Running linter (clippy)..."
cargo clippy -- -D warnings

echo "Step 3: Building the project..."
cargo build --verbose

echo "Step 4: Running tests..."
cargo test --verbose

echo "--- Autobuild Script Completed Successfully! ---"
