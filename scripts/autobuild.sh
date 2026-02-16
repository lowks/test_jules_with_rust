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

echo "Step 4: Running backend tests..."
cargo test --verbose -- --test-threads=1

echo "Step 5: Running UI tests..."
# Check for Python and Playwright
if ! command -v python3 &> /dev/null; then
    echo "python3 could not be found, skipping UI tests"
    exit 0
fi

# Ensure Playwright is installed
python3 -m pip install playwright --quiet
python3 -m playwright install chromium --with-deps &> /dev/null

# Ensure port 8000 is clear
kill $(lsof -t -i :8000) 2>/dev/null || true

# Start the server in the background
cargo run > server.log 2>&1 &
SERVER_PID=$!

# Ensure the server is killed on exit
cleanup() {
    echo "Cleaning up server (PID: $SERVER_PID)..."
    kill $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

# Wait for server to start
MAX_RETRIES=30
COUNT=0
UP=0
while [ $COUNT -lt $MAX_RETRIES ]; do
    if grep -q "Rocket has launched" server.log; then
        echo "Server is up!"
        UP=1
        break
    fi
    sleep 1
    COUNT=$((COUNT + 1))
done

if [ $UP -eq 0 ]; then
    echo "Server failed to start. Content of server.log:"
    cat server.log
    exit 1
fi

# Run UI tests
if python3 tests_ui/test_sorting.py; then
    echo "UI tests passed!"
else
    echo "UI tests failed!"
    exit 1
fi

echo "--- Autobuild Script Completed Successfully! ---"
