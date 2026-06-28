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
