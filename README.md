# RGB-PQ

**RGB-style client-side validated assets using BTQ P2MR outputs as post-quantum single-use seals, over Bitcoin Quantum regtest/testnet.**

```
RGB-PQ = RGB consensus (rgb-protocol v0.11.1-rc.10)
       + BTQ P2MR / Dilithium post-quantum seals (btq-core)
       + an auditable Rust adapter that binds RGB transitions onto BTQ seals
```

> **Integration candidate for BTQ regtest/testnet.** This is *not* Bitcoin
> mainnet post-quantum RGB and makes no claim of production Bitcoin value
> safety. See [`SECURITY.md`](SECURITY.md).

---

## Table of contents

- [What this is](#what-this-is)
- [Architecture](#architecture)
- [The two commitment schemes](#the-two-commitment-schemes)
- [Why this stack](#why-this-stack)
- [Quick start](#quick-start)
- [Repository layout](#repository-layout)
- [Crate reference](#crate-reference)
- [How a seal is closed (end to end)](#how-a-seal-is-closed-end-to-end)
- [Verification budget & DoS defence](#verification-budget--dos-defence)
- [Running tests](#running-tests)
- [Configuration](#configuration)
- [Quality gates](#quality-gates)
- [What is real vs local-only](#what-is-real-vs-local-only)
- [Known limitations](#known-limitations)
- [Security model](#security-model)
- [Roadmap](#roadmap)
- [License](#license)

---

## What this is

RGB-PQ binds **RGB client-side-validated state transitions** onto **BTQ P2MR
outputs** whose spending path is a **post-quantum Dilithium signature**.

- **RGB** supplies the asset/contract layer: issuance, state transitions, and
  consignment validation — all client-side, all real (vendored `rgbcore` /
  `rgbstd` / `schemata`, v0.11.1-rc.10 production track).
- **BTQ** (`btq-core`, a Bitcoin Core fork) supplies the chain: SegWit v2 P2MR
  outputs (32-byte Merkle-root witness program, no key path), `bc1z`/`qcrt1z`
  addresses, and `OP_CHECKSIGDILITHIUM` script-path ownership.
- **RGB-PQ** is the glue: a canonical seal type, two commitment schemes, a chain
  backend that plugs into RGB's `ResolveWitness`, an indexer, a resolver, and a
  deterministic local e2e harness — all in auditable Rust.

The post-quantum property applies to the **seal ownership path** (the P2MR
Dilithium leaf), not to the whole system. See
[Security model](#security-model).

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         RGB-PQ workspace                             │
│                                                                      │
│  ┌─────────────────── external/ (vendored, path-deps) ─────────────┐ │
│  │  rgb-consensus (rgbcore)  ── RGB consensus / ResolveWitness      │ │
│  │  rgb-ops       (rgbstd)   ── Stock / ContractBuilder / indexer   │ │
│  │  rgb-schemas   (schemata) ── NIA schema + issuance examples      │ │
│  │  btq-core      (btqd)     ── BTQ node (C/C++, JSON-RPC)          │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                ▲                                     │
│                                │ path-deps + [patch.crates-io]       │
│                                ▼                                     │
│  ┌─────────────────────── crates/ (the adapter) ───────────────────┐ │
│  │                                                                 │ │
│  │  rgb-pq-core    typed errors (12) · domain separation (2)       │ │
│  │       │         · VerifyLimits / DoS defence / BudgetGuard      │ │
│  │       ▼                                                         │ │
│  │  rgb-pq-seal    canonical BtqP2mrSeal (binary/text/test vec)    │ │
│  │       │                                                         │ │
│  │       ▼                                                         │ │
│  │  rgb-pq-commit  opret binder ──┐                                │ │
│  │                 p2mr-ret binder ┘ (two commitment schemes)      │ │
│  │       │                                                         │ │
│  │       ▼                                                         │ │
│  │  rgb-pq-chain   BtqChainBackend trait · RPC client · indexer    │ │
│  │       │         (in-mem + SQLite, reorg rollback)               │ │
│  │       ▼                                                         │ │
│  │  rgb-pq-resolver  SealResolver→SealState · ResolveWitness bridge│ │
│  │       │                                                         │ │
│  │       ▼                                                         │ │
│  │  rgb-pq-rgb     real RGB NIA issuance / consignment validation  │ │
│  │  rgb-pq-tx      BTQ tx construction helpers                     │ │
│  │  rgb-pq-bench   verification-latency microbenchmarks            │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                ▲                                     │
│                                │                                     │
│  ┌─────────────────────── tests/rgb-pq-e2e ────────────────────────┐ │
│  │  deterministic offline flow  +  live BTQ regtest close           │ │
│  │  (opret + p2mr-ret, both live-verified)                         │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

The BTQ integration lives in a **seal substrate / `ResolveWitness` layer**. RGB
consensus itself is **unmodified** — the adapter implements RGB's chain-backend
trait (`ResolveWitness`) over BTQ RPC, exactly mirroring the upstream
`EsploraClient` reference (`rgb-ops/src/indexers/esplora_blocking.rs`).

### The chain-backend seam

RGB v0.11.1 has exactly one chain-facing trait used by consensus validation:

```rust
// rgb-consensus/src/validation/validator.rs:90
pub trait ResolveWitness {
    fn resolve_witness(&self, witness_id: Txid) -> Result<WitnessStatus, WitnessResolverError>;
    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError>;
}
```

`rgb-pq-resolver::BtqWitnessResolver` implements this over a BTQ node, so the
RGB validator can confirm witness transactions on BTQ.

## The two commitment schemes

RGB requires the closing transaction to carry the LNPBP-4 multi-protocol
commitment (the validator hard-checks for an OP_RETURN or P2TR output). RGB-PQ
implements **two** schemes, both complete and live-verified:

### Scheme 1 — Opret (Phase 1, visible)

The commitment lives in an **OP_RETURN output** of the closing tx. Simplest,
visible on chain. The closing tx:

```
vin:  [old P2MR seal]            # closed by Dilithium leaf
vout: [recipient P2MR seal]      # new open seal
vout: [OP_RETURN: rgbpq commit]  # RGB anchor (opret)
vout: [change]                   # optional
```

### Scheme 2 — P2MR-ret (Phase 2, the tapret-equivalent for P2MR)

P2MR has **no internal key / key tweak** (unlike Taproot), so "Tapret" cannot
be reused literally. Instead, the RGB commitment is a **dedicated leaf** in the
P2MR script tree alongside the PQ ownership leaf:

```
P2MR script tree (both leaves at depth 1)
├── PQ spend leaf        (Dilithium / ML-DSA ownership script)
└── RGB commitment leaf  (unspendable OP_RETURN script carrying the commitment)

p2mr_root = TapbranchHash(TapleafHash(pq_leaf), TapleafHash(commitment_leaf))
```

No separate OP_RETURN output — the commitment is bound into the seal itself.
More private, less chain bloat.

> **Chicken-and-egg (resolved):** the P2MR-ret leaf must be fixed *before* the
> P2MR output exists, so the leaf does **not** embed the outpoint — it carries
> only `magic || tag || chain_id || mpc_commitment` (59 B). The outpoint binding
> is implicit: the leaf lives in the very P2MR output the seal names.

| Property | Opret | P2MR-ret |
|---|---|---|
| Commitment location | OP_RETURN output | P2MR script-tree leaf |
| Visible on chain | yes | no (hidden in root) |
| Chain bloat | +1 output | 0 extra outputs |
| Needs `-datacarriersize` | yes (>83 B) | no |
| Merkle math | none | Tapleaf + Tapbranch (BIP-340 tagged, verified vs node) |
| Live-verified | ✓ | ✓ (root matches node byte-for-byte) |

## Why this stack

- Uses the actively maintained **`rgb-protocol` v0.11.1-rc.10** production
  track (Zoe Paltibà), **not** the old RGB-WG v0.12 line.
- Uses **`btq-ag/btq-core`** for P2MR + Dilithium.
- `[patch.crates-io]` forces the whole graph onto vendored versions (no
  duplication, fully reproducible).
- Real `bitcoin = 0.32` types (RGB's pin) line up across the boundary.

See [`docs/repo-notes.md`](docs/repo-notes.md) for the full vendored-repo
table and the reusable upstream tools that were found.

## Quick start

```bash
# 1. fetch vendored upstream repos (rgb-protocol + btq-core)
./scripts/setup-external.sh

# 2. run the full local e2e (builds/starts a BTQ regtest node, runs both
#    commitment schemes + offline guarantees; falls back to deterministic
#    offline flow if the node can't build)
./scripts/e2e-local.sh
```

Or just the Rust tests (no BTQ node needed):

```bash
cargo test --workspace --all-features
```

Run the benchmarks:

```bash
cargo test -p rgb-pq-bench --release -- --nocapture
```

## Repository layout

```
external/                 vendored upstream (gitignored; fetched by setup-external.sh)
  rgb-consensus/          RGB consensus core          (lib: rgbcore)
  rgb-ops/                RGB stdlib / Stock           (lib: rgbstd)
  rgb-schemas/            Official RGB schemata         (lib: schemata)
  btq-core/               BTQ node (C/C++ autotools)    (btqd / btq-cli)

crates/
  rgb-pq-core/            typed errors (Comp 12) · domain separation (Comp 2)
                          · VerifyLimits / DoS defence
  rgb-pq-seal/            canonical BtqP2mrSeal (Comp 1) + test vectors
  rgb-pq-commit/          opret binder (Comp 7) + p2mr-ret binder (Phase 2)
  rgb-pq-chain/           BtqChainBackend (Comp 3) + RPC client (Comp 4)
                          + indexer in-mem/SQLite (Comp 5)
  rgb-pq-resolver/        SealResolver→SealState (Comp 6) + ResolveWitness bridge
  rgb-pq-rgb/             real RGB NIA issuance / consignment verify (Comp 8)
  rgb-pq-tx/              BTQ tx construction helpers (Comp 9)
  rgb-pq-bench/           verification-latency benchmarks

tests/rgb-pq-e2e/         local end-to-end (Comp 10, 13): offline + live
scripts/
  setup-external.sh       fetch vendored repos
  build-btq.sh            build btq-core (optional, for live e2e)
  e2e-local.sh            full local runner
docs/                     architecture, security, commitment, verification budget
.github/workflows/ci.yml  fmt + clippy -D warnings + test + doc + offline e2e
SECURITY.md               full threat model (17+ sections)
ARCHITECTURE.md           verified API map with file:line refs into upstream
```

## Crate reference

| Crate | Role | Key types |
|---|---|---|
| `rgb-pq-core` | errors + domain-sep + DoS limits | `RgbPqError`, `VerifyLimits`, `DoSError`, `BudgetGuard`, `Domain` |
| `rgb-pq-seal` | canonical seal | `BtqP2mrSeal`, `BtqChainId`, `PqSigAlgo`, `CommitmentLocator`, `ConfirmationPolicy` |
| `rgb-pq-commit` | commitment binding | `RgbPqCommitment` (opret), `P2mrRetTree`/`verify_p2mr_ret` (p2mr-ret), `compute_tapleaf_hash`/`compute_tapbranch_hash` |
| `rgb-pq-chain` | chain backend | `BtqChainBackend`, `BtqRpcClient`, `MemIndexer`, `SqliteIndexer` |
| `rgb-pq-resolver` | seal resolution | `SealResolver`, `SealState`, `BtqWitnessResolver` (`ResolveWitness`) |
| `rgb-pq-rgb` | RGB integration | `issue_nia_to_btq_seal`, `validate_consignment` |
| `rgb-pq-tx` | tx helpers | `BtqTxOps`, `append_opret_commitment`, `seal_from_p2mr` |
| `rgb-pq-bench` | benchmarks | `run_suite`, `BenchResult` |

## How a seal is closed (end to end)

The closing-transaction construction is the load-bearing detail. Live-verified
ordering:

```
1. sendtop2mr <tree> <amount>                  → funding txid, p2mr_id
2. generatetoaddress 1 <miner>                 → confirm funding
3. createp2mrspend <p2mr_id> <dest> <amt> <fee>→ unsigned raw hex
4. append_opret_commitment(hex, seal, mpc)     → +OP_RETURN output   [opret]
   — or —
   build_p2mr_ret_tree(chain, mpc, pq_leaf)    → root bound into seal  [p2mr-ret]
5. signp2mrtransaction <hex> <p2mr_id>         → signed (P2MR/Dilithium witness)
6. sendrawtransaction <signed_hex>             → close txid
7. generatetoaddress 1 <miner>                 → confirm close
8. verify commitment on chain + inclusion proof
```

The node requires `-datacarriersize=256` (opret payload is 127 B > the 83 B
default) and `-fallbackfee`; both are set by `scripts/e2e-local.sh`.

## Verification budget & DoS defence

RGB-PQ treats verification time as a **security boundary**. Verification latency
(CPU/parsing/proof-checking) is bounded and kept **separate from finality
latency** (confirmation depth, governed by `ConfirmationPolicy`).

Every verification path enforces `VerifyLimits` and **fails closed** (returns
`Unknown` / `ClosedInvalid`, never `ClosedValid`) on breach:

| Limit | Default |
|---|---|
| `max_p2mr_tree_depth` | 32 |
| `max_commitment_leaf_size` | 256 B |
| `max_witness_size` | 16 KB |
| `max_candidate_spends_per_seal` | 8 |
| `max_scan_window` | 64 |
| `max_resolver_time_ms` | 5000 |

The dominant cost is **PQ witness size** (Dilithium2 sig ≈ 2420 B), not the P2MR
Merkle path (O(depth), trivial). See [`docs/verification-budget.md`](docs/verification-budget.md).

## Running tests

```bash
# full unit + property + integration suite
cargo test --workspace --all-features          # 116 tests

# no-default-features (SQLite off)
cargo test --workspace --no-default-features

# offline e2e (no node needed)
cargo test -p rgb-pq-e2e -- --nocapture

# live e2e (needs a running btqd; see scripts/e2e-local.sh)
RGBPQ_BTQ_RPC=http://127.0.0.1:28543 \
RGBPQ_BTQ_USER=btq RGBPQ_BTQ_PASS=btqpass \
RGBPQ_BTQ_CHAIN=bitcoin-quantum-regtest \
  cargo test -p rgb-pq-e2e -- --nocapture
```

## Configuration

The live e2e reads these env vars:

| Var | Default | Purpose |
|---|---|---|
| `RGBPQ_BTQ_RPC` | — | node RPC URL (e.g. `http://127.0.0.1:28543`) |
| `RGBPQ_BTQ_USER` | `btq` | RPC user |
| `RGBPQ_BTQ_PASS` | `btqpass` | RPC password |
| `RGBPQ_BTQ_CHAIN` | `bitcoin-quantum-regtest` | chain id |
| `RGBPQ_BTQ_WALLET` | — | wallet name (wallet-scoped RPC) |
| `RGBPQ_SKIP_LIVE` | `0` | skip the live path in `e2e-local.sh` |

## Quality gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

All gates are green. The workspace is `#![forbid(unsafe_code)]` everywhere.

## What is real vs local-only

**Real (live-verified):**
- RGB issuance / transition / consignment / validation (vendored `rgbcore`/`rgbstd`/`schemata`)
- BTQ P2MR creation / spend + Dilithium script-path signing (`btq-core`)
- RGB MPC commitment embedding (opret via `rgbcore::dbc::opret`; p2mr-ret via verified Merkle math)
- Inclusion proofs (`gettxoutproof`/`verifytxoutproof`)
- `ResolveWitness` over BTQ RPC
- P2MR-ret Merkle math matches `btq-core` consensus byte-for-byte

**Local-only (clearly marked, deterministic, tested):**
- The regtest node itself (the target)
- The in-memory indexer variant (SQLite is the persistent one)
- Test Dilithium keys (fixtures, not for value)

Nothing in the security-critical path is mocked.

## Known limitations

- Targets BTQ regtest/testnet only — **never** Bitcoin mainnet.
- P2MR-ret commitment leaf uses a plain OP_RETURN-style script; a future
  hardening could use a dedicated unspendable leaf opcode if BTQ adds one.
- The `ChainNet` mapping (BTQ → RGB stand-in) is documented but not a true
  RGB-level chain identity.
- Live Dilithium key export from the wallet is indirect (via DILITHIUM_PUBKEYHASH
  leaves); a future wallet RPC exposing raw pubkeys would simplify the PQ-leaf
  path.

## Security model

See [`SECURITY.md`](SECURITY.md) for the full model (17+ sections): RGB
client-side-validation assumptions, BTQ P2MR assumptions, why P2MR alone is not
full post-quantum security, short vs long quantum exposure, reorg/indexer/RPC
trust, commitment replay, cross-chain confusion, DoS defence, and the
"before real-value deployment" checklist.

**Key points:**
- secp256k1 ownership is **unrepresentable** as a `PqSigAlgo` — never silently
  downgraded.
- Domain separation prevents cross-chain / cross-seal confusion.
- Verification time is a security boundary (bounded, fail-closed).

## Roadmap

- [x] Phase 1 — Opret over BTQ P2MR spend (live-verified)
- [x] Phase 2 — P2MR-ret commitment leaf (live-verified, Merkle math matches node)
- [x] Verification budget + DoS fail-closed + latency benchmarks
- [x] Resolver p2mr-ret branching (both commitment schemes symmetric in resolver)
- [x] Real RGB transfer (`transfer_nia_btq` with genesis input wiring)
- [x] Dilithium PQ leaf helper (`dilithium_pubkeyhash_leaf_hex`)
- [x] ChainNet mapping invariant tests
- [x] Reorg end-to-end integration test (indexer rollback + live `invalidateblock`)
- [x] Phase 3 — multi-protocol P2MR commitment tree (`MultiProtocolP2mrTree`)
- [x] Internal security audit (`docs/audit.md`, 10 findings)
- [x] Dilithium key rotation (`rotate_dilithium_key`, live-verified with real PQ leaf)
- [x] Strict live e2e: Dilithium leaf + key rotation + reorg simulation + both commitment schemes

## License

Apache-2.0, matching the upstream `rgb-protocol` and `btq-core` licenses.
