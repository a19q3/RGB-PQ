#!/usr/bin/env bash
# Fetch the vendored upstream repositories that rgb-pq depends on via path-deps.
#
# These are NOT committed (see .gitignore). Running this script makes a clean
# checkout self-contained and reproducible.
#
# Repos:
#   rgb-protocol/rgb-consensus  v0.11.1-rc.10  (Rust, lib rgbcore)
#   rgb-protocol/rgb-ops        v0.11.1-rc.10  (Rust, lib rgbstd)
#   rgb-protocol/rgb-schemas    v0.11.1-rc.10  (Rust, lib schemata)
#   btq-ag/btq-core             0.3.2          (C/C++ node, built separately)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT="$ROOT/external"
mkdir -p "$EXT"

clone_if_absent() {
    local url="$1"; local dir="$2"
    if [ -d "$EXT/$dir" ]; then
        echo "[setup] $dir already present, skipping"
    else
        echo "[setup] cloning $url -> external/$dir"
        git clone --depth 1 "$url" "$EXT/$dir"
    fi
}

clone_if_absent https://github.com/rgb-protocol/rgb-consensus.git rgb-consensus
clone_if_absent https://github.com/rgb-protocol/rgb-ops.git       rgb-ops
clone_if_absent https://github.com/rgb-protocol/rgb-schemas.git   rgb-schemas
clone_if_absent https://github.com/btq-ag/btq-core.git            btq-core

echo "[setup] done. External repos are in $EXT"
echo "[setup] To build the BTQ node, see scripts/build-btq.sh (optional; needed for live e2e)."
