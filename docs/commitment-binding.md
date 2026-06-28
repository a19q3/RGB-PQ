# Commitment binding

RGB anchors a `TransitionBundle` into a Bitcoin/BTQ transaction via an LNPBP-4
multi-protocol commitment (MPC) embedded with a DBC proof. The RGB validator
requires the closing transaction to carry an **OP_RETURN** (opret) **or** P2TR
(tapret) output and checks the proof method matches
(`rgb-consensus/src/validation/validator.rs:464`).

## RGB-PQ choice: OP_RETURN (opret)

P2MR is neither `is_op_return` nor `is_p2tr`, so the RGB commitment **cannot**
live inside the P2MR witness program. Therefore the closing BTQ transaction
carries **two** commitment-bearing artefacts:

1. **The P2MR spend** — proves post-quantum (Dilithium) ownership of the seal.
2. **An OP_RETURN output** — carries the RGB MPC commitment.

Closing tx shape:

```
vin:  [old P2MR seal]            # closed by Dilithium leaf
vout: [recipient P2MR seal]      # new open seal
vout: [OP_RETURN: rgbpq commit]  # RGB anchor (opret)
vout: [change]                   # optional
```

We do **not** implement tapret hiding (per the brief): opret is the simplest
explicit, locally-testable commitment.

## The RGB-PQ commitment payload

`rgb_pq_commit::RgbPqCommitment` wraps the 32-byte MPC commitment with the
metadata needed to bind it unambiguously:

```
MAGIC("RGBPQCM") || TAG("rgbpq:commitment:v0") || chain(1)
        || seal_txid(32) || seal_vout(4 LE) || mpc(32) || seal_digest(32)
```

`seal_digest` is a domain-separated digest over the seal, so a commitment for
one seal cannot be replayed for another.

## Verification

- `verify_commitment_in_outputs(seal, outputs)` scans decoded tx outputs for
  the payload and returns `Found` / `Missing` / `Duplicate` / `WrongChain` /
  `WrongSeal` / `Malformed`.
- RGB consensus independently verifies the opret anchor via
  `Anchor<OpretProof>::convolve(contract_id, bundle_id)` then
  `dbc_proof.verify(commitment, &tx)`.

---

# Scheme 2 — P2MR-ret (commitment in the P2MR script tree)

P2MR-ret is the **tapret-equivalent for P2MR** (Phase 2). P2MR has no internal
key / key tweak (unlike Taproot), so instead of tweaking an output key, the RGB
commitment is placed as a **dedicated leaf** in the P2MR script tree alongside
the PQ ownership leaf:

```text
P2MR script tree (depth 1 for both leaves)
├── PQ spend leaf          (Dilithium / ML-DSA ownership script)
└── RGB commitment leaf    (unspendable OP_RETURN script carrying the commitment)
```

The P2MR output root commits to **both**:

```text
p2mr_root = TapbranchHash(TapleafHash(pq_leaf), TapleafHash(commitment_leaf))
```

No separate OP_RETURN output is needed — the commitment is bound into the seal
itself. This is more private and produces less chain bloat than opret.

## Why not Tapret literally?

P2MR (BIP-360) deliberately removes Taproot's internal key and key-path spend.
The witness program *is* the Merkle root directly (no tweak). So "Tapret" —
which hides a commitment by tweaking the Taproot output key — **cannot be
reused unchanged**. P2MR-ret instead commits via a leaf, which is the natural
commitment surface for a tree-root output.

## The chicken-and-egg constraint (important)

The opret payload embeds the seal's outpoint (txid/vout). But for P2MR-ret,
the leaf must be fixed **before** the P2MR output exists (the output's witness
program *is* the root that commits to the leaf), so the outpoint is not yet
known. Therefore the P2MR-ret commitment payload **does not embed the outpoint**
— it carries only `magic || tag || chain_id || mpc_commitment` (59 bytes).

The outpoint binding is **implicit**: the commitment leaf lives in the very
P2MR output the seal names, so being in the tree *is* the binding. The chain is
still domain-separated (regtest vs testnet).

## Exact Merkle math (verified against `btq-core` consensus)

Reproduced byte-for-byte from `btq-core/src/script/interpreter.cpp`:

- **Tapleaf** = `SHA256(SHA256("TapLeaf")||SHA256("TapLeaf")||leaf_version||CompactSize(len)||script)`
- **Tapbranch** = `SHA256(SHA256("TapBranch")||SHA256("TapBranch")||min(a,b)||max(a,b))`
  (lexicographic ordering of the two 32-byte child hashes)
- **P2MR root** = the Merkle root directly (no tweak)

This was **live-verified**: a Rust-built P2MR-ret tree produces a root that
matches the node's `getnewp2mraddress` root byte-for-byte, and the seal can be
funded + spent via the PQ leaf with the commitment leaf provably bound.

## Verification

- `verify_p2mr_ret(seal, mpc, pq_leaf_script)` recomputes the tree from
  `seal.chain_id` + `mpc` + the PQ leaf, and checks the root equals
  `seal.p2mr_root`.
- `P2mrRetProof::verify_against(root)` verifies the commitment-leaf Merkle
  proof.
- `find_commitment_in_tree(seal, leaves, root)` recovers the (chain, mpc) from
  a node-reported tree's leaf list.

## Comparison

| Property | Opret (Phase 1) | P2MR-ret (Phase 2) |
|---|---|---|
| Commitment location | OP_RETURN output in closing tx | leaf in P2MR script tree |
| Visible on chain | yes (OP_RETURN) | no (hidden in tree root) |
| Chain bloat | +1 output | 0 extra outputs |
| Outpoint binding | explicit (in payload) | implicit (leaf is in the seal output) |
| Needs `-datacarriersize` | yes (>83 B) | no |
| Live-verified | yes | yes |
