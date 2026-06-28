# Security Audit — RGB-PQ Internal Review

This document is a **systematic internal security review** of every
critical path in RGB-PQ. It is NOT a substitute for a formal third-party
audit, but it establishes the reviewable evidence trail that one would
start from.

## Scope

Reviewed components:
- Seal encoding & domain separation (`rgb-pq-seal`, `rgb-pq-core`)
- Both commitment schemes: opret + p2mr-ret (`rgb-pq-commit`)
- Chain backend, RPC client, indexer (`rgb-pq-chain`)
- Resolver + ResolveWitness bridge (`rgb-pq-resolver`)
- RGB integration: issuance, transfer (`rgb-pq-rgb`)
- DoS-defence / verification budget (`rgb-pq-core::limits`)
- ChainNet mapping (BTQ → RGB stand-in)

## Findings

### F-1: ChainNet mapping is a documented compromise (LOW)

**Status:** Accepted, documented, tested.

BTQ chains map to Bitcoin `ChainNet` variants (`BitcoinRegtest`,
`BitcoinTestnet3`) because RGB v0.11.1 has no BTQ variant. The mapping is:
- `BtqChainId::BitcoinQuantumRegtest → ChainNet::BitcoinRegtest`
- `BtqChainId::BitcoinQuantumTestnet → ChainNet::BitcoinTestnet3`

**Risk:** An attacker could theoretically present a real Bitcoin regtest
transaction as a BTQ witness if `check_chain_net` only compares `ChainNet`
(not the genesis hash). **Mitigated:** `BtqRpcClient::verify_network()`
checks `getblockchaininfo.chain == "regtest"/"test"` against the BTQ node,
and the `BtqChainId` field in the seal independently enforces chain identity
via domain separation. The `stand_in_chain_hash` test documents that the
stand-in hash is a Bitcoin hash, not BTQ's, so the real chain identity
depends on the explicit `BtqChainId` + `verify_network`, not on the stand-in.

**Invariant tests:** `chainnet_stand_in_hash_is_documented_and_stable`,
`chainnet_mapping_is_exhaustive_for_btq`.

### F-2: secp256k1 ownership is type-level unrepresentable (PASS)

**Status:** Enforced by the type system.

`PqSigAlgo` has only `Dilithium2` and `Dilithium5`. There is no secp256k1
variant. Code requiring `PqSigAlgo` cannot accidentally accept secp256k1.
The resolver checks `is_pq_owner_algo(seal.owner_algo)` at step 5 and
rejects non-PQ with `ClosedInvalid(WrongOwnershipPath)`.

### F-3: Domain separation prevents cross-chain/cross-seal confusion (PASS)

Every canonical digest includes `rgbpq:v0` + chain string + `p2mr` +
version. The `canonical_digest` changes whenever any field changes
(property-tested with `proptest`). Cross-chain confusion is rejected at
`BtqChainId::from_domain_str()` (mainnet/testnet/signet/regtest-as-bitcoin
all rejected).

### F-4: DoS-defence: all verification paths fail closed (PASS)

Every verification path (`SealResolver::resolve`,
`verify_commitment_in_outputs_bounded`, `verify_p2mr_ret_bounded`,
`CommitmentPayload::scan`) enforces `VerifyLimits` and maps `DoSError` to
`Unknown`/`ClosedInvalid`, never `ClosedValid`. The `BudgetGuard`
enforces wall-clock time. Tested: `dos_scan_window_rejected`,
`dos_oversized_output_rejected`, `dos_resolver_fails_closed_on_time`.

### F-5: RPC client never logs secrets (PASS)

`safe_endpoint()` strips credentials from URLs before embedding them in
errors. Basic-auth is sent in the `Authorization` header, never logged.
The `BtqAuth::UserPass` struct does not implement `Display`.

### F-6: Merkle math matches btq-core consensus byte-for-byte (PASS)

`compute_tapleaf_hash` and `compute_tapbranch_hash` reproduce the exact
BIP-340 tagged-hash formula from `btq-core/src/script/interpreter.cpp`.
Live-verified: a Rust-built P2MR-ret tree root matches the node's
`getnewp2mraddress` root byte-for-byte.

### F-7: OP_RETURN commitment visible on chain (INFORMATIONAL)

The opret scheme puts the commitment in a visible OP_RETURN output. This
is by design (Phase 1, simplest path). The p2mr-ret scheme (Phase 2)
hides the commitment in the P2MR root. Both are implemented and tested.

### F-8: Key rotation not automated (MEDIUM → addressed)

**Status:** Now implemented via `rotate_dilithium_key()`.

Key rotation means: generate a new Dilithium key, create a new P2MR seal
owned by the new key, transfer RGB state to the new seal, and close the
old seal. The old key becomes irrelevant once the old seal is closed.
There is no in-place key replacement within an existing P2MR output.

### F-9: Indexer is a cache, not consensus (PASS)

The indexer tracks watched outpoints and spending txs. It does not make
consensus decisions. The resolver re-checks outpoint existence, P2MR root,
leaf hash, ownership algo, commitment binding, and confirmation depth
against the chain backend.

### F-10: Reorg handling (PASS)

`SealResolver` returns `SealState::ReorgRisk` when confirmations <
required depth. `MemIndexer::rollback(to_height)` clears spends above
the fork point. `SqliteIndexer` does the same via SQL. Integration test
`indexer_rollback_then_spend_cleared` verifies the rollback clears spend
data.

## Recommendations for a third-party audit

1. Formally verify the Merkle math (`compute_tapleaf_hash`,
   `compute_tapbranch_hash`) against BIP-340 + BIP-360 reference.
2. Review the `ChainNet` mapping for any scenario where a Bitcoin tx could
   be accepted as a BTQ witness.
3. Fuzz the seal decoder (`BtqP2mrSeal::from_binary`) and commitment
   decoder (`RgbPqCommitment::decode`) with malformed inputs.
4. Review the RPC client for timeout/retry behaviour under network
   partitions.
5. Audit the multi-protocol P2MR tree for tree-balancing attacks (a
   malicious peer could craft a degenerate tree).
