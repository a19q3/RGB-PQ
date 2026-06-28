# Release-readiness checklist

Before considering RGB-PQ for anything beyond local regtest/testnet
experimentation, every item below must be satisfied. Most are **not** done.

## Must-have

- [ ] Formal security audit of the adapter (`rgb-pq-*` crates).
- [ ] Audit of the `ChainNet` mapping (BTQ → RGB stand-in) and its consequences.
- [ ] Dilithium parameter decision (Dilithium2 vs Dilithium5) vs deployment
      horizon, with FIPS 204 alignment.
- [ ] Persistent, redundant indexer deployment (SQLite path hardened, or a real
      DB); no single-node trust.
- [ ] Fee / locktime / RBF policy for the closing transaction.
- [ ] Reviewed commitment scheme (opret vs tapret) and bandwidth analysis.
- [ ] Operational security for Dilithium keys (HSM / secure enclave). The test
      keys in this repo are **fixtures**, not for value.
- [ ] Reorg/finality policy reviewed for the target chain depth.
- [ ] Consignment validation hardened against DoS (large/malformed consignments).
- [ ] Replay protection across chains (domain separation tests stay green).
- [ ] Full integration tests against a long-running BTQ testnet, not just
      regtest.

## Out of scope (explicitly not pursued)

- Bitcoin mainnet support.
- Any claim of production Bitcoin value safety.
- "Complete post-quantum Bitcoin" — only the P2MR ownership path is PQ.

## Current state

- All 15 components implemented.
- Real RGB issuance + BTQ P2MR/Dilithium (when a node is available) + opret
  commitment + `ResolveWitness` bridge.
- Deterministic offline e2e passes from a clean checkout.
- See `SECURITY.md` §17 for the full "before real-value deployment" list.
