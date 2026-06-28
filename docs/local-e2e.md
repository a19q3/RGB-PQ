# Local end-to-end setup

## Prerequisites

- Rust stable (≥ 1.85): the workspace pins `rust-toolchain.toml`.
- Git.
- For the **live** path only: a buildable `btq-core` (C/C++ autotools). On
  macOS arm64:
  ```bash
  xcode-select --install
  brew install automake libtool boost pkg-config libevent
  ```

## One command

```bash
./scripts/e2e-local.sh
```

This script:

1. runs `scripts/setup-external.sh` to fetch the vendored repos;
2. builds `btq-core` if `btqd` is not already present;
3. starts a `btqd` regtest node on port `28543`;
4. waits for RPC readiness;
5. creates a wallet and mines 110 blocks;
6. runs `cargo run -p rgb-pq-e2e` with the node configured;
7. stops the node cleanly;
8. stores logs under `./run/e2e.log`;
9. exits non-zero on failure.

If building/starting `btq-core` is not possible, the script **falls back** to
the deterministic offline flow and prints that the live node was not exercised.

## Running the offline flow only

```bash
RGBPQ_SKIP_LIVE=1 ./scripts/e2e-local.sh
# or directly:
cargo run -p rgb-pq-e2e
```

## Running the live flow against an existing node

If you already run a `btqd` regtest node, point the e2e at it:

```bash
RGBPQ_BTQ_RPC=http://127.0.0.1:28543 \
RGBPQ_BTQ_USER=btq \
RGBPQ_BTQ_PASS=btqpass \
RGBPQ_BTQ_CHAIN=bitcoin-quantum-regtest \
  cargo run -p rgb-pq-e2e
```

## Logs and artifacts

- Node data dir: `run/btq-regtest/`
- Run log: `run/e2e.log`
