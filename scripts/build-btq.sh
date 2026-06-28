#!/usr/bin/env bash
# Build the BTQ node (btq-core, a Bitcoin Core fork) from source.
#
# Produces `external/btq-core/src/btqd` and `external/btq-core/src/btq-cli`.
# This is OPTIONAL for the Rust workspace (which compiles without it) but
# REQUIRED for the live local end-to-end flow.
#
# macOS arm64 prerequisites (install once):
#   xcode-select --install
#   brew install automake libtool boost pkg-config libevent
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BTQ="$ROOT/external/btq-core"
BTQD="$BTQ/src/btqd"
BTQCLI="$BTQ/src/btq-cli"

if [ -x "$BTQD" ] && [ -x "$BTQCLI" ]; then
    echo "[build-btq] btqd already built at $BTQD"
    exit 0
fi

if [ ! -d "$BTQ" ]; then
    echo "[build-btq] btq-core not found; run scripts/setup-external.sh first" >&2
    exit 1
fi

echo "[build-btq] building btq-core (this takes a while on first run)..."
cd "$BTQ"

# The stray 104MB garbage file in the tree (src/stdOfUtC) is harmless but huge;
# remove it to keep the tree clean.
rm -f "$BTQ/src/stdOfUtC"

if [ ! -f configure ]; then
    ./autogen.sh
fi
./configure --with-gui=no --disable-bench --disable-tests --disable-fuzz-binary
make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" src/btqd src/btq-cli

echo "[build-btq] done: $BTQD"
