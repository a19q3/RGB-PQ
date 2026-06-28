# RGB-PQ

**RGB-style client-side validated assets using BTQ P2MR outputs as post-quantum
single-use seals, over Bitcoin Quantum regtest/testnet.**

```text
RGB-PQ = RGB consensus (rgb-protocol v0.11.1)
       + BTQ P2MR / Dilithium post-quantum seals (btq-core)
       + an auditable Rust adapter that binds RGB transitions onto BTQ seals
```

> This is an **integration candidate** targeting BTQ regtest/testnet. It is
> **not** Bitcoin mainnet post-quantum RGB and makes no claim of production
> Bitcoin value safety. See [SECURITY.md](SECURITY.md).

---

## Why this stack

- Uses the actively maintained **`rgb-protocol` v0.11.1-rc.10** production-track
  stack (Zoe Paltibà), **not** the old RGB-WG v0.12 line.
- Uses **`btq-ag/btq-core`** (a Bitcoin Core fork) for P2MR (SegWit v2)
  outputs, `bc1z`/`qcrt1z` addresses, P2MR script-tree root commitments, and
  Dilithium post-quantum script-path ownership.
- RGB client-side validation semantics are kept upstream-compatible; the BTQ
  integration lives in a **seal substrate / chain-backend layer**.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full verified API map and
design.

## Quick start

```bash
# 1. fetch vendored upstream repos (rgb-protocol + btq-core)
./scripts/setup-external.sh

# 2. run the local e2e (builds/starts a BTQ regtest node if possible,
#    otherwise runs the deterministic offline flow)
./scripts/e2e-local.sh
```

Or just the Rust tests (no BTQ node needed):

```bash
cargo test --workspace --all-features
cargo test -p rgb-pq-e2e -- --nocapture
```

## Layout

```
external/                 vendored upstream (rgb-consensus, rgb-ops, rgb-schemas, btq-core)
crates/
  rgb-pq-core/            typed errors (12) + domain separation (2)
  rgb-pq-seal/            canonical BtqP2mrSeal (1) + test vectors
  rgb-pq-commit/          RGB transition commitment binder / opret anchor (7)
  rgb-pq-chain/           BtqChainBackend trait (3) + RPC client (4) + indexer (5)
  rgb-pq-resolver/        P2MR seal resolver -> SealState (6) + ResolveWitness bridge
  rgb-pq-rgb/             real RGB NIA issuance / consignment verify (8)
  rgb-pq-tx/              BTQ tx construction helpers (9)
tests/rgb-pq-e2e/         local end-to-end (10, 13)
scripts/                  setup-external.sh, build-btq.sh, e2e-local.sh
docs/                     architecture, security, how-to docs (15)
```

## What is real

- RGB issuance / transition / consignment / validation: **real** (vendored
  `rgbcore`/`rgbstd`/`schemata`).
- BTQ P2MR creation/spend + Dilithium script-path signing: **real** (`btq-core`).
- RGB MPC commitment embedding (opret): **real** (`rgbcore::dbc::opret`).
- Inclusion proofs: **real** (`gettxoutproof`).
- `ResolveWitness` over BTQ RPC: **real**.

## What is local-only

- The regtest node itself (the target).
- The in-memory indexer variant (clearly marked; SQLite is the persistent one).
- Test Dilithium keys (fixtures, not for value).

## Quality gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --no-default-features
cargo doc --workspace --no-deps
```

## License

Apache-2.0, matching the upstream `rgb-protocol` and `btq-core` licenses.
