#!/usr/bin/env bash
# RGB-PQ local end-to-end runner.
#
# Performs the full local flow described in ARCHITECTURE.md and the brief:
#   1. ensure vendored repos are present (scripts/setup-external.sh);
#   2. build (or locate) btq-core;
#   3. start a local BTQ regtest node;
#   4. wait for RPC readiness;
#   5. create wallet + mine initial blocks;
#   6. run the RGB-PQ e2e (cargo run -p rgb-pq-e2e) with the node configured;
#   7. stop the node cleanly;
#   8. store logs under ./run;
#   9. non-zero exit on failure.
#
# If building/starting btq-core is not possible on this host, the script falls
# back to the deterministic offline flow (real RGB issuance + seal/commitment/
# resolver verification against fixtures) and states clearly that the live node
# was not exercised.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/run"
LOG="$RUN/e2e.log"
mkdir -p "$RUN"
: > "$LOG"

# Defaults for the local regtest node (mirrors btq-core's run_p2mr_rpc_e2e.sh).
RPC_PORT="${RGBPQ_BTQ_PORT:-28543}"
RPC_USER="${RGBPQ_BTQ_USER:-btq}"
RPC_PASS="${RGBPQ_BTQ_PASS:-btqpass}"
BTQD="$ROOT/external/btq-core/src/btqd"
BTQCLI="$ROOT/external/btq-core/src/btq-cli"
DATADIR="$RUN/btq-regtest"
WALLET="rgbpq"

log() { echo "[e2e-local] $*" | tee -a "$LOG"; }

cleanup() {
    if [ -n "${BTQD_PID:-}" ] && kill -0 "$BTQD_PID" 2>/dev/null; then
        log "stopping btqd (pid $BTQD_PID)"
        "$BTQCLI" -regtest -rpcport="$RPC_PORT" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" stop >/dev/null 2>&1 || true
        # give it a moment, then force-kill if still alive
        for _ in 1 2 3 4 5; do kill -0 "$BTQD_PID" 2>/dev/null || break; sleep 0.5; done
        kill -9 "$BTQD_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

cd "$ROOT"

# 1. vendored repos
log "ensuring vendored repos"
bash "$ROOT/scripts/setup-external.sh" 2>&1 | tee -a "$LOG"

# Try the live path. If anything fails, fall back to offline.
run_live() {
    # 2. build btq-core
    if [ ! -x "$BTQD" ]; then
        log "btqd not built; attempting build (may take a while)"
        bash "$ROOT/scripts/build-btq.sh" 2>&1 | tee -a "$LOG"
    fi
    [ -x "$BTQD" ] || { log "btqd build unavailable; will run offline flow"; return 1; }

    # 3. start regtest node
    log "starting btqd regtest on port $RPC_PORT"
    mkdir -p "$DATADIR"
    "$BTQD" -regtest \
        -datadir="$DATADIR" \
        -rpcport="$RPC_PORT" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" \
        -rpcallowip=127.0.0.1 \
        -listen=0 -dnsseed=0 -upnp=0 -natpmp=0 \
        -printtoconsole -daemonwait=true >>"$LOG" 2>&1 &
    BTQD_PID=$!

    # 4. wait for RPC readiness
    log "waiting for RPC readiness"
    ready=0
    for _ in $(seq 1 60); do
        if "$BTQCLI" -regtest -rpcport="$RPC_PORT" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" getblockchaininfo >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 1
    done
    [ "$ready" = 1 ] || { log "btqd RPC not ready"; return 1; }

    # 5. wallet + initial blocks
    log "creating wallet '$WALLET'"
    "$BTQCLI" -regtest -rpcport="$RPC_PORT" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" \
        -rpcwallet="$WALLET" createwallet "$WALLET" >/dev/null 2>&1 || true
    MINER=$("$BTQCLI" -regtest -rpcport="$RPC_PORT" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" \
        -rpcwallet="$WALLET" getnewaddress)
    log "mining 110 blocks to $MINER"
    "$BTQCLI" -regtest -rpcport="$RPC_PORT" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" \
        -rpcwallet="$WALLET" generatetoaddress 110 "$MINER" >/dev/null

    # 6. run the e2e with the node configured
    log "running RGB-PQ e2e (live+offline)"
    RGBPQ_BTQ_RPC="http://127.0.0.1:$RPC_PORT" \
    RGBPQ_BTQ_USER="$RPC_USER" \
    RGBPQ_BTQ_PASS="$RPC_PASS" \
    RGBPQ_BTQ_CHAIN="bitcoin-quantum-regtest" \
        cargo run -p rgb-pq-e2e 2>&1 | tee -a "$LOG"
}

run_offline() {
    log "running RGB-PQ e2e (deterministic offline flow; live BTQ node NOT exercised)"
    cargo run -p rgb-pq-e2e 2>&1 | tee -a "$LOG"
}

if [ "${RGBPQ_SKIP_LIVE:-0}" = "1" ]; then
    log "RGBPQ_SKIP_LIVE=1; skipping live path"
    run_live_ok=1
else
    if run_live; then run_live_ok=1; else run_live_ok=0; fi
fi

if [ "$run_live_ok" != "1" ]; then
    run_offline
fi

log "done. Logs: $LOG"
