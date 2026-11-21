#!/usr/bin/env bash
set -euo pipefail

if command -v cargo >/dev/null 2>&1; then
    echo "Installing besynx-daemon via cargo..."
    cargo install --git https://github.com/whysooraj/besynx.git besynx-daemon
    echo "Successfully installed besynx-daemon"
else
    echo "Rust/Cargo required. Install from https://rustup.rs first."
    exit 1
fi
