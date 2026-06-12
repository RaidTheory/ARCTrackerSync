#!/usr/bin/env bash
# Build and run ARCTracker Sync natively on Linux (for ARC Raiders via Proton).
#
# Packet capture needs CAP_NET_RAW. This grants it on the built binary with a
# one-time `setcap` (asks for sudo once) so the GUI itself runs unprivileged —
# preferable to running the whole app as root.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="target/release/arctracker-sync"

echo "==> Building release binary"
cargo build --release

echo "==> Granting CAP_NET_RAW to $BIN (needs sudo once)"
sudo setcap cap_net_raw+ep "$BIN"

echo "==> Launching"
exec "$BIN"
