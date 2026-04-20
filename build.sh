#!/usr/bin/env bash
# build.sh — HiveMine build script
# Installs Rust if needed, then builds the hivemine binary in release mode.
#
# Usage:
#   chmod +x build.sh && ./build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== HiveMine Build Script ==="
echo ""

# ─── 1. Check / install Rust ───────────────────────────────────────────────────

if source "$HOME/.cargo/env" 2>/dev/null && cargo --version &>/dev/null; then
    echo "[✓] Rust found: $(rustc --version)"
else
    echo "[!] Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    source "$HOME/.cargo/env"
    echo "[✓] Rust installed: $(rustc --version)"
fi

# ─── 2. Ensure nightly is available (snarkVM sometimes needs it) ──────────────
# Use stable by default
rustup default stable 2>/dev/null || true
rustup update stable 2>/dev/null || true

# ─── 3. Build ─────────────────────────────────────────────────────────────────

echo ""
echo "Building hivemine (release)..."
echo "Note: First build downloads snarkVM parameters (~500MB). Please be patient."
echo ""

# Set RUST_LOG for build output
export RUST_LOG=warn

cargo build --release 2>&1

echo ""
echo "=== Build Complete ==="
echo "Binary: $SCRIPT_DIR/target/release/hivemine"
echo ""
echo "Usage examples:"
echo "  # Benchmark mode (60s, reports MH/s):"
echo "  ./target/release/hivemine --benchmark --wallet aleo1YOUR_ADDRESS_HERE"
echo ""
echo "  # Pool mining mode:"
echo "  ./target/release/hivemine --wallet aleo1YOUR_ADDRESS_HERE --pool aleo.hk.zk.work:10003"
echo ""
echo "  # 4 parallel agents:"
echo "  ./target/release/hivemine --wallet aleo1YOUR_ADDRESS_HERE --pool aleo.hk.zk.work:10003 --agents 4"
echo ""
