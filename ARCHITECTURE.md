# RGB-PQ — Architecture Note

> **Scope of this document.** This is the architecture note required *before*
> implementation. It records what was inspected in the upstream repositories,
> the verified APIs that the integration is built against, the design decisions
> forced by those APIs, and the boundary between "real" and "local-harness"
> behaviour. It is intentionally concrete: every claim about an upstream API is
> backed by a `file:line` reference into the vendored clones under
> `external/`.

---

## 1. What RGB-PQ is

```text
RGB-PQ = RGB-style client-side validated assets
       using BTQ P2MR outputs as post-quantum single-use seals
       over Bitcoin Quantum regtest / testnet
```

RGB supplies client-side-validated smart-contract / asset state. BTQ
(`btq-core`, a Bitcoin Core fork) supplies a chain whose outputs can be owned by
**post-quantum** Dilithium signatures through the **P2MR** (Pay-to-Merkle-Root)
script-path. RGB-PQ binds RGB state transitions onto BTQ P2MR seals: a seal is
*closed* by spending the P2MR output via its Dilithium script leaf, and the RGB
transition commitment is anchored into that same closing transaction.

**Target description (canonical):** `P2MR-backed RGB single-use seals over
Bitcoin Quantum regtest/testnet`.

This is **not** Bitcoin mainnet post-quantum RGB. See `SECURITY.md`.

---

## 2. Repositories inspected (cloned, not guessed)

| Repo | Role | Language | Version | Lib name |
|---|---|---|---|---|
| `rgb-protocol/rgb-consensus` | RGB consensus core | Rust | `0.11.1-rc.10` | `rgbcore` |
| `rgb-protocol/rgb-ops` | RGB stdlib / containers / stock / indexers | Rust | `0.11.1-rc.10` | `rgbstd` (+ `rgbinvoice`) |
| `btq-ag/btq-core` | BTQ node (Bitcoin Core fork): P2MR, Dilithium, RPC, regtest | C/C++ (autotools) | `0.3.2` | `btqd` / `btq-cli` |

These are the **Zoe Paltiba / `rgb-protocol` production-track** stack (Cargo
`authors = ["Zoe Faltibà <zoefaltiba@gmail.com>"]`), **not** the old
RGB-WG v0.12 line. The reason this matters: v0.11.1-rc.x is the actively
maintained track (last pushes 2026-04..06) and is the one whose
`ResolveWitness` seam we integrate against.

`btq-core` is a **C/C++ autotools** project. The RGB-PQ integration is
therefore a **Rust adapter that speaks JSON-RPC to a `btqd` process**; we do not
reimplement P2MR/Dilithium consensus in Rust. This is the correct boundary: the
chain's consensus rules live in `btq-core`, and client-side validation lives in
`rgbcore`. RGB-PQ is the glue + the seal substrate.

---

## 3. Verified upstream APIs (the contract we integrate against)

All references are into `external/`.

### 3.1 The RGB chain-backend seam: `ResolveWitness`

This is the single most important finding. RGB does **not** have a generic
`ChainSource`/`Indexer`/`Anchor` trait. It has exactly one chain-facing trait
used by consensus validation:

```rust
// rgb-consensus/src/validation/validator.rs:90
pub trait ResolveWitness {
    fn resolve_witness(&self, witness_id: Txid) -> Result<WitnessStatus, WitnessResolverError>;
    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError>;
}
```

```rust
// rgb-consensus/src/validation/validator.rs:106
pub enum WitnessStatus {
    Unresolved,
    Resolved(Tx, WitnessOrd),
}
```

```rust
// rgb-consensus/src/vm/contract.rs:267
pub enum WitnessOrd {
    Mined(WitnessPos),   // confirmed in L1 at height + timestamp
    Tentative,           // valid mempool tx, not yet mined
    Archived,            // stale; treated as "seal not closed"
    Ignored,
}
```

The reference implementation is `EsploraClient`
(`rgb-ops/src/indexers/esplora_blocking.rs:37-75`): fetch the tx, fetch its
status, map a mined block `(height, time)` to
`WitnessOrd::Mined(WitnessPos::bitcoin(height, time))` and an unmined tx to
`WitnessOrd::Tentative`; verify the genesis chain hash in `check_chain_net`.

**Implication:** our BTQ chain backend implements `ResolveWitness` by calling
BTQ RPC (`getrawtransaction` + `getblockheader`). This is the exact seam the
brief asks for ("existing RGB seal resolver abstractions / chain backend
abstractions").

### 3.2 The RGB seal types

The RGB seal that represents *"the outpoint that will be spent to close the
seal"* is `GraphSeal`:

```rust
// rgb-consensus/src/seals/txout/blind.rs:52
pub struct BlindSeal<Id: SealTxid> { pub txid: Id, pub vout: Vout, pub blinding: u64 }
// rgb-consensus/src/operation/seal.rs:36
pub type GenesisSeal = BlindSeal<Txid>;   // single, txid known
pub type GraphSeal   = BlindSeal<TxPtr>;  // witness-relative
// rgb-consensus/src/seals/txout/seal.rs:96
pub enum TxPtr { WitnessTx, Txid(Txid) }
```

A `GraphSeal` with `txid = TxPtr::WitnessTx` is precisely "the outpoint whose
txid becomes known only once the witness transaction that closes a *previous*
seal is finalized" — i.e. the chained-seal model. `SecretSeal` is the concealed
form (commitment of a `BlindSeal`, `seals/secret.rs:41`).

**Implication:** RGB-PQ seals (our `BtqP2mrSeal`) are an **adapter-side
super-type**: they carry the extra BTQ-specific fields (p2mr root, script leaf
hash, owner algo, commitment locator, confirmation policy) that pure RGB
`BlindSeal` does not. At the RGB boundary we derive a `GraphSeal`
(`(txid_or_witness, vout, blinding)`) from a `BtqP2mrSeal`. The BTQ fields are
enforced by our resolver, not by RGB consensus.

### 3.3 The commitment / anchor mechanism (load-bearing)

RGB anchors a `TransitionBundle` into a Bitcoin tx via an **MPC (LNPBP-4)
commitment** embedded with a **DBC proof** that is either **opret** (OP_RETURN)
or **tapret** (P2TR key tweak):

```rust
// rgb-consensus/src/validation/commitments.rs:74
pub enum DbcProof { Tapret(TapretProof), Opret(OpretProof) }
// rgb-consensus/src/dbc/proof.rs:60
pub enum Method { OpretFirst = 0x00, TapretFirst = 0x01 }
```

The validator **hard-requires** the closing tx to contain an OP_RETURN **or**
P2TR output and that the proof method matches the found output type
(`rgb-consensus/src/validation/validator.rs:464-484`):

```rust
let Some(output) = witness.tx.output.iter().find(|out|
    out.script_pubkey.is_op_return() || out.script_pubkey.is_p2tr()
) else { return Err(Failure::NoDbcOutput(witness.txid)); };
```

**Implication (decisive for the design):** the RGB commitment **cannot live
inside the P2MR witness program** (RGB would reject it — it is neither
`is_op_return` nor `is_p2tr`). Therefore the closing BTQ transaction carries
**two** commitment-bearing artefacts:

1. **The P2MR spend itself** — proves post-quantum ownership of the seal
   (Dilithium script-path). This is what makes it a *post-quantum* single-use
   seal.
2. **An OP_RETURN output** — carries the RGB MPC commitment (`OpretProof`).
   This is what binds the RGB state transition to the closing tx. This is the
   "visible commitment output" the brief explicitly permits, and the simplest
   one that is locally end-to-end testable. We do **not** implement tapret
   hiding (per the brief).

So a closing tx looks like:

```text
vin:  [<old P2MR seal outpoint>]                      # closed by Dilithium leaf
vout: [<recipient P2MR seal>]                         # new seal (open)
vout: [<OP_RETURN: rgbpq commitment>]                 # RGB anchor (opret)
vout: [<change>]                                      # optional
```

The RGB `Anchor<OpretProof>` is reconstructed client-side from the witness tx
and verified by `rgbcore`'s validator exactly as for ordinary Bitcoin RGB.

### 3.4 Chain / network modelling

RGB has its own `Layer1` + `ChainNet` enums
(`rgb-consensus/src/operation/layer1.rs:41,58`); `ChainNet` has **no BTQ
variant** (Bitcoin/Liquid only). `check_chain_net` compares
`ChainNet::chain_hash()` to the backend's genesis hash.

**Decision:** RGB-PQ introduces its own strongly-typed `BtqChainId`
(`BitcoinQuantumRegtest`, `BitcoinQuantumTestnet`) with domain separation. At
the RGB boundary we map BTQ onto a chosen `ChainNet` stand-in
(`ChainNet::BitcoinRegtest` / `BitcoinTestnet3`) and document this as an
explicit, isolated mapping. RGB consensus does not need to know about BTQ; it
only needs a consistent `ChainNet` whose `chain_hash()` the BTQ backend can
match. The mapping is *documented and tested*, never silent, and never
downgrades ownership.

### 3.5 BTQ P2MR primitive

P2MR is **SegWit version 2**; the witness program is the **32-byte Merkle root**
of a script tree. There is **no key path**; the control-block parity bit is
fixed to `1`; spending is script-path only.

- `src/addresstype.h:93` `WitnessV2P2MR { unsigned char m_merkle_root[32]; }`
- `src/addresstype.cpp:196` scriptPubKey = `OP_2 PUSH32 <root>` (34 bytes)
- `src/key_io.cpp:68` bech32m, witness v2 → `bc1z`-style prefix; regtest HRP is
  **`qcrt`**, so regtest P2MR addresses look like `qcrt1z…`
- `src/script/interpreter.cpp:2107` `VerifyP2MRCommitment` walks the control
  block (`1 + 32*N` bytes) via `ComputeTapbranchHash` and checks the root.

### 3.6 BTQ Dilithium

- Opcodes `OP_CHECKSIGDILITHIUM = 0xbb` … `OP_DILITHIUM_PUBKEY = 0xbf`
  (`src/script/script.h:220`). **Blocked in ordinary P2TR tapscript**, but
  **enabled** under `SigVersion::P2MR_TAPSCRIPT`
  (`src/script/interpreter.cpp:1272`). This is exactly the leaf type we use.
- Dilithium2 sizes: pk 1312 B, sk 2560 B, sig 2420 B
  (`src/crypto/dilithium_key.h:29`). Dilithium5 also defined.

### 3.7 BTQ RPC surface (verified, not guessed)

P2MR wallet RPCs (`src/wallet/rpc/p2mr.cpp`): `getnewp2mraddress`,
`sendtop2mr`, `listp2mr`, `getp2mrinfo`, `createp2mrspend`,
`signp2mrtransaction`, `testp2mrtransaction`. Dilithium RPCs
(`src/wallet/rpc/dilithium.cpp`): `getnewdilithiumaddress`,
`signtransactionwithdilithium`, etc. Standard Bitcoin Core RPCs inherited:
`getrawtransaction`, `createrawtransaction`, `decoderawtransaction`,
`signrawtransactionwithwallet`, `getblock`, `getblockheader`, `getblockhash`,
`gettxout`, `generatetoaddress` (hidden), `gettxoutproof`/`verifytxoutproof`
(`src/rpc/txoutproof.cpp:22,123`) for inclusion proofs. **Note:** there is no
`signrawtransaction` (only `…withwallet` / `…withkey`).

### 3.8 BTQ e2e reference

`run_p2mr_rpc_e2e.sh` (repo root) is the canonical P2MR lifecycle over RPC:
start `btqd -regtest -rpcport=28543 -rpcuser=btq -rpcpassword=btqpass`, create
wallet, mine 110 blocks, `getnewp2mraddress` (tree `[{"depth":0,
"leaf_version":192,"script":"51"}]` = `OP_TRUE`), `sendtop2mr`, mine,
`createp2mrspend` → `signp2mrtransaction` → `testp2mrtransaction` →
`sendrawtransaction` → mine. Our e2e mirrors this but uses a **Dilithium leaf**
(not `OP_TRUE`) and inserts the RGB OP_RETURN commitment.

---

## 4. Layered design

```text
RGB-PQ workspace
│
├── external/                         vendored upstream (read-only basis)
│   ├── rgb-consensus/  (rgbcore)        ┐ RGB client-side validation
│   ├── rgb-ops/        (rgbstd)         ┘ contracts, stock, consignment, ResolveWitness
│   └── btq-core/                        BTQ node (built externally, JSON-RPC)
│
├── crates/
│   ├── rgb-pq-seal/      Component 1,2  canonical BtqP2mrSeal + domain separation
│   ├── rgb-pq-commit/    Component 7    RGB transition commitment binder (opret)
│   ├── rgb-pq-chain/     Component 3,4,5 BtqChainBackend trait, RPC client, indexer
│   ├── rgb-pq-resolver/  Component 6    P2MR seal resolver (SealState) + ResolveWitness bridge
│   ├── rgb-pq-rgb/       Component 8    real RGB issuance/transfer/consignment glue
│   ├── rgb-pq-tx/        Component 9    BTQ tx construction helpers
│   └── rgb-pq-core/      facade + typed errors (Component 12) re-exporting the above
│
├── tests/
│   └── rgb-pq-e2e/       Component 10,13 local end-to-end test crate (deterministic)
│
└── scripts/e2e-local.sh  Component 10   build + run btq regtest + cargo e2e
```

Each crate has a single responsibility and a narrow public API. `rgb-pq-core`
is the optional facade.

### Dependency direction (no cycles)

```text
rgb-pq-seal ──► rgb-pq-commit
     │
     ▼
rgb-pq-chain (RPC, indexer, backend trait)
     │
     ▼
rgb-pq-resolver ──► rgbcore::validation::ResolveWitness
     │
     ▼
rgb-pq-rgb (Stock/builder/consignment) ──► rgbstd, rgbcore
     │
     ▼
rgb-pq-tx (BTQ tx helpers) ──► rgb-pq-chain, rgb-pq-seal, rgb-pq-commit
```

`rgbcore`/`rgbstd` are pulled from the vendored `external/` via path deps (with
a `[patch]`/workspace override) so the workspace is self-contained and
reproducible. `bitcoin = 0.32` (RGB's pinned version) is reused for `OutPoint`/
`Txid`/`Transaction`/bech32m so types line up across the boundary.

---

## 5. The closing-transaction commitment (Component 7) in detail

The binder produces an RGB `Anchor<OpretProof>` plus the bytes for the
OP_RETURN output. Concretely:

1. Collect the `TransitionBundle`(s) for the witness tx → `BundleId`.
2. `mpc::Message::from(bundle_id)`, convolve under `protocol_id = ContractId`
   → `mpc::Commitment` (this is `Anchor::convolve`, `dbc/anchor.rs`).
3. Embed the commitment into the witness tx via
   `<Tx as EmbedCommitVerify<Commitment, OpretFirst>>::embed_commit`
   (`rgb-consensus/src/dbc/opret/tx.rs:44`), which writes it into the **first
   OP_RETURN output's scriptPubKey**. The returned `OpretProof` is empty but is
   the typed object RGB validates.
4. Our `BtqP2mrSeal` carries a `CommitmentLocator` naming *which* output (by
   vout) holds the OP_RETURN, so the resolver can find it unambiguously and
   reject duplicate/conflicting commitments.

The binder's domain-separated digest includes `rgbpq:v0`, chain id, seal type
`p2mr`, txid, vout, p2mr_root, script_leaf_hash, owner_algo,
commitment_locator, confirmation_policy — every one of which is a
documented test that the digest *changes* when it changes.

---

## 6. Real vs local-harness boundary

| Capability | Status | Notes |
|---|---|---|
| RGB issuance / transition / consignment / validation | **Real** | via vendored `rgbcore`+`rgbstd` `Stock`/`ContractBuilder`/`Validator` |
| RGB `ResolveWitness` against BTQ | **Real** | BTQ RPC `getrawtransaction`+`getblockheader` |
| BTQ P2MR output creation / spend | **Real, live-verified** | `btq-core` RPC; OP_RETURN commitment insertion into the unsigned spend, then `signp2mrtransaction` |
| BTQ Dilithium script-path signing | **Real** | `signp2mrtransaction` in the node (PQ path is btq-core's own `feature_p2mr.py`) |
| RGB MPC commitment embedding | **Real, live-verified** | OP_RETURN payload `RGBPQCM…` confirmed on a mined regtest block |
| Inclusion proof | **Real, live-verified** | `gettxoutproof` + `verifytxoutproof` round-trips the close tx |
| `btqd` regtest lifecycle | **Real** | started/stopped by `scripts/e2e-local.sh` |
| Persistent indexer storage | **SQLite (real)** + **in-memory (local-only, tested)** | persistent path optional via feature |
| `btq-core` build | **External** | C/C++ autotools; `scripts/build-btq.sh` builds it if `btqd` is absent |

### Live close ordering (verified)

The closing-transaction construction is the load-bearing detail. It is:

```text
1. sendtop2mr <tree> <amount>                     -> funding txid, p2mr_id
2. generatetoaddress 1 <miner>                     -> confirm funding
3. createp2mrspend <p2mr_id> <dest> <amt> <fee>    -> unsigned raw hex
4. append_opret_commitment(unsigned_hex, seal, mpc) -> modified hex (+OP_RETURN output)
5. signp2mrtransaction <modified_hex> <p2mr_id>    -> signed hex (P2MR/Dilithium witness)
6. sendrawtransaction <signed_hex>                 -> close txid
7. generatetoaddress 1 <miner>                     -> confirm close
```

Step 4 is the RGB-PQ insertion: it decodes the unsigned raw tx, appends an
`OP_RETURN` output carrying `RgbPqCommitment`, and re-encodes — all via the real
`bitcoin` consensus codec, so the result is byte-identical to a hand-built tx.
The node requires `-datacarriersize=256` (the payload is 127 B > the 83 B
default) and `-fallbackfee` (before fee estimation has data); both are set by
`scripts/e2e-local.sh`.

**Nothing in the security-critical path is mocked.** The only "local-only"
pieces are (a) the in-memory indexer variant (clearly marked, deterministic,
tested) and (b) the regtest node itself (which is the *point* — this targets
regtest/testnet, never mainnet).

If, on a given machine, `btq-core` cannot be built, the e2e falls back to a
**deterministic recorded-fixture harness** that replays real BTQ RPC
responses, and the run report states explicitly that the live node was not
exercised. This is documented in `docs/local-e2e.md`.

---

## 7. Constraints honoured from the brief

- RGB client-side validation semantics are kept upstream-compatible; the BTQ
  integration lives in the seal-substrate / chain-backend layer
  (`ResolveWitness` + our resolver). The only RGB-stack change contemplated is
  an isolated, documented `ChainNet` mapping at the boundary, and only if
  unavoidable (preferred: no RGB edit, map at adapter).
- No silent downgrade to non-PQ ownership: `BtqP2mrSeal.owner_algo` is a
  supported-PQ-only enum; secp256k1 ownership is rejected where PQ is required.
- No implicit default network: `BtqChainId` must be specified.
- No ambiguous treatment of Bitcoin / BTQ / Taproot / ordinary RGB seals:
  enforced by domain separation + typed seals + tests.
- Local e2e is deterministic and runnable from a clean checkout via
  `./scripts/e2e-local.sh` or `cargo test -p rgb-pq-e2e --all-features`.

---

## 8. Open items deferred to implementation (tracked in todos)

- Exact `[patch]`/path-dep wiring so the workspace compiles against vendored
  `rgbcore`/`rgbstd` without hitting crates.io drift.
- Whether to emit the OP_RETURN via `btq-core` RPC (raw-tx construction) or by
  post-processing the unsigned hex from `createp2mrspend` (preferred — keeps
  coin selection in the node).
- Dilithium test-key generation: `btq-core` generates keys internally for
  wallet leaves; for a *known* deterministic fixture key we may need to import
  a Dilithium key (`importdilithiumkey`) or construct a leaf from a fixed seed.
  To be confirmed against `src/wallet/p2mr.cpp` during Component 9.

These are implementation details, not architecture risks; the seams above are
fixed by the verified APIs in §3.
