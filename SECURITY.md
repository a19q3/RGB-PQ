# Security Model — RGB-PQ

This document records the security assumptions, threat model, and known
limitations of RGB-PQ. It is deliberately explicit about what is **not**
claimed. RGB-PQ targets **BTQ regtest/testnet only**; it is **not** Bitcoin
mainnet post-quantum RGB and makes no claim of production Bitcoin value safety.

> **One-line summary:** RGB-PQ binds RGB client-side-validated state transitions
> onto BTQ P2MR outputs whose spending path is a post-quantum Dilithium
> signature, over Bitcoin Quantum regtest/testnet. The post-quantum property
> applies to the *seal ownership path*, not to the whole system.

---

## 1. What RGB-PQ is and is not

| Claim | Status |
|---|---|
| RGB consensus / client-side validation is real | ✅ vendored `rgbcore`/`rgbstd` v0.11.1-rc.10 |
| BTQ P2MR outputs are real | ✅ `btq-core` node |
| Dilithium script-path ownership is real | ✅ `btq-core` (`P2MR_TAPSCRIPT`) |
| Targets BTQ regtest/testnet | ✅ |
| Targets Bitcoin mainnet | ❌ **explicitly not** |
| Production Bitcoin value safety | ❌ **not claimed** |
| Complete post-quantum Bitcoin | ❌ P2MR is one PQ path, not "all of Bitcoin is PQ" |

---

## 2. RGB client-side validation assumptions

RGB is client-side validated: a recipient verifies a **consignment** against the
Bitcoin/BTQ transaction graph themselves. RGB-PQ inherits RGB's assumptions:

- The consignment must be complete (all referenced transitions, schemas,
  scripts, and witness anchors included).
- The verifier must independently resolve witness transactions from a chain
  backend they trust (here, a BTQ node they run).
- RGB consensus correctness is assumed correct as shipped by
  `rgb-protocol` v0.11.1-rc.10. RGB-PQ does **not** modify RGB consensus.

## 3. BTQ P2MR assumptions

- P2MR is SegWit v2; the witness program is the 32-byte Merkle root of a script
  tree. There is **no key path**; spending is script-path only.
- The control-block parity bit is fixed to `1`.
- The Merkle inclusion of the spending leaf is verified by `btq-core` consensus
  (`VerifyP2MRCommitment`, `src/script/interpreter.cpp:2107`).
- RGB-PQ trusts `btq-core`'s consensus rules for P2MR validation (it does not
  re-implement them in Rust).

## 4. Dilithium / post-quantum ownership assumptions

- The spending leaf uses `OP_CHECKSIGDILITHIUM` (opcode `0xbb`), which is
  **enabled under `P2MR_TAPSCRIPT`** and **blocked under ordinary P2TR
  tapscript** (`src/script/interpreter.cpp:1272`).
- Dilithium2 keys: pk 1312 B, sig 2420 B. Dilithium5 (pk 2592, sig 4627) is
  feature-gated.
- RGB-PQ **never** accepts a secp256k1 ownership path where PQ ownership is
  required: `PqSigAlgo` has no secp256k1 variant, and `OwnerAlgoError::
  Secp256k1NotAllowed` is returned on any attempt.

## 5. Why P2MR alone is not full post-quantum security

P2MR makes the **ownership path** of a specific output post-quantum. It does
**not** make the entire system post-quantum, because:

- **Hash-based address binding** still relies on classical assumptions for
  address derivation where secp256k1 is involved elsewhere in a wallet.
- **Funding transactions** that create P2MR outputs may be signed with
  classical keys (the funding path), exposing them to a future quantum
  adversary if funds dwell in classical outputs before reaching P2MR.
- **The RGB layer** itself uses secp256k1 for some identity/blinding operations;
  these are not PQ.

Concretely, the PQ guarantee is: *once value is committed to a P2MR output
spendable only via a Dilithium leaf, and that output has not yet been spent,
spending it requires breaking Dilithium.*

## 6. Short-exposure vs long-exposure quantum attack assumptions

- **Short-exposure**: value that moves quickly from a classical output into a
  P2MR output and is spent soon after. The classical-exposure window is small.
  Assume reasonable protection under "harvest now, decrypt later" only if the
  dwell time in classical outputs is negligible.
- **Long-exposure**: value resting in a P2MR output for years. The PQ
  assumption rests on Dilithium remaining unbroken over that horizon. If
  Dilithium parameters are later found weak, long-dwelling outputs are at risk
  until rotated. **Address reuse increases this risk** (see §13).

## 7. Chain reorg risk

- BTQ regtest has `fPowNoRetargeting = true`; testnet does not. Reorgs are
  possible on either.
- RGB-PQ models reorgs explicitly: the indexer supports `rollback(to_height)`
  and `rescan_from(from_height)`, and the resolver returns
  `SealState::ReorgRisk { confirmations, required }` when a close is confirmed
  but below the seal's `ConfirmationPolicy` depth.
- A seal is only considered `ClosedValid` once its spending tx meets the
  configured finality depth (`OneConf` by default; use `Depth(N)` for higher
  assurance).

## 8. Indexer equivocation risk

- The indexer is a **cache**; it does not make consensus decisions. Final
  verification is done by the resolver against the chain backend.
- A compromised/buggy indexer could return stale or wrong spend data. The
  resolver re-checks outpoint existence, P2MR root, leaf, ownership algo,
  commitment binding, and confirmation depth against the backend.
- For high assurance, run your own BTQ node + indexer; do not trust a
  third-party indexer.

## 9. RPC trust assumptions

- The RPC client authenticates with `-rpcuser`/`-rpcpassword` (HTTP Basic).
  **Credentials must be kept secret**; the client never logs them (errors carry
  the endpoint URL with credentials stripped).
- RPC is trusted for: transaction/status fetch, broadcast, inclusion proofs.
- RPC is **not** trusted for: consensus correctness (that is `btq-core`
  consensus), or for the binding digest (recomputed client-side).

## 10. Commitment replay risk

- The RGB-PQ commitment payload is domain-separated (`rgbpq:commitment:v0`) and
  binds chain + seal outpoint + MPC commitment + a seal-binding digest. A
  commitment for one seal cannot be replayed for another (wrong-seal/wrong-chain
  are rejected).
- Duplicate conflicting commitments in a single closing tx are rejected
  (`CommitmentError::Duplicate`).

## 11. Cross-chain confusion risk

- `BtqChainId` has only `BitcoinQuantumRegtest` / `BitcoinQuantumTestnet`.
  Mainnet is rejected at parse time. Non-BTQ Bitcoin chains (testnet3/4, signet,
  regtest-as-bitcoin) are rejected.
- Every canonical digest includes the chain domain string, so a regtest seal
  and a testnet seal with otherwise-identical fields hash differently.
- P2TR / ordinary Taproot outputs are rejected where P2MR is required
  (`ChainConfusion::OrdinaryTaproot`).

## 12. Malformed consignment risk

- RGB consensus rejects malformed consignments (`ValidationError`). RGB-PQ adds
  typed errors for malformed seals (`MalformedSealError`) and commitments
  (`CommitmentError::Malformed`).
- Always validate a received consignment with `validate_consignment(...)` using
  a resolver you control before accepting state.

## 13. Stale proof risk & address reuse

- A consignment + its witness anchors can go **stale** if the chain reorgs past
  the witness. Re-validate before accepting.
- **Address reuse** is dangerous for PQ hygiene: reusing a P2MR address
  increases exposure and correlation. Generate a fresh P2MR seal per transfer.

## 14. Key rotation

- Dilithium keys are not currently rotatable in-place within RGB-PQ; rotation
  means creating a new P2MR seal with a fresh leaf and transferring RGB state
  to it. There is no automated rotation path yet.

## 15. Why secp256k1 ownership must not be treated as PQ

- secp256k1 (ECDSA/Schnorr) is broken by a sufficiently large quantum computer
  (Shor). A seal whose ownership path is secp256k1 provides **no** PQ security.
- RGB-PQ makes secp256k1 ownership unrepresentable as a `PqSigAlgo`, so code
  that requires PQ ownership cannot accidentally accept it. This is enforced by
  the type system and tested.

## 16. What is local-regtest only

- The default local e2e uses a `btqd` regtest node (or the deterministic offline
  flow). Regtest coins have **no value**.
- The in-memory indexer variant is local-only (clearly marked). Use the SQLite
  indexer for any persistent use.

## 17. What would be required before real-value deployment

This list is intentionally daunting. RGB-PQ is an **integration candidate**,
not a product:

- A formal audit of the RGB-PQ adapter and the `ChainNet` mapping.
- A mainnet-capable BTQ chain (BTQ mainnet) with audited consensus, **if** BTQ
  mainnet is ever considered — which is out of scope here.
- Dilithium parameter review against the deployment horizon (consider
  Dilithium5 / future FIPS updates).
- Persistent, audited indexer deployment; no reliance on a single node.
- Replay/fee/locktime policy for the closing transaction.
- A reviewed commitment scheme decision (opret vs tapret) and its bandwidth
  implications.
- Operational security for Dilithium keys (HSM/secure enclave; this repo's test
  keys are fixtures, **not** for value).

## Reporting a vulnerability

Please open a private issue or contact the maintainers directly. Do not publicly
disclose security-relevant bugs before a fix is coordinated.
