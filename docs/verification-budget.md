# Verification budget & DoS defence

RGB-PQ verifies client-supplied data (consignments, P2MR trees, witnesses,
commitment proofs, candidate spends). This document records the budget model,
the enforced limits, and the benchmark targets.

## Two latencies, kept separate (never conflated)

```text
verification latency   = CPU / parsing / proof-checking time (what the verifier does)
finality latency       = waiting for confirmations / reorg safety (chain-dependent)
```

P2MR/PQ may increase **verification** latency; **finality** latency is governed
by `ConfirmationPolicy` (depth of confirmations). RGB-PQ never collapses these
into a single vague "timeout".

## Where the cost actually is

```text
P2MR validation cost
≈ script leaf hash               (cheap, O(1) hash)
+ control block / Merkle path    (cheap, O(depth))
+ tapscript execution            (cheap)
+ PQ signature verification      (DOMINANT — Dilithium2 sig ≈ 2420 B, pk ≈ 1312 B)
```

**The Merkle path is not the bottleneck; the PQ witness size is.** Larger
witnesses → larger tx → higher relay/block bandwidth → slower indexing and
proof fetching. The implementation accounts for this via `max_witness_size`.

P2MR-ret adds one **off-chain commitment-leaf inclusion proof** over opret
(`verify_p2mr_ret` recomputes the tree + checks the Merkle proof). Benchmarked
at single-digit microseconds.

## Enforced limits (`VerifyLimits`)

Every verification path enforces these and **fails closed** (returns `Unknown` /
`ClosedInvalid` / `Err(DoSError)`, never `ClosedValid`):

| Limit | Default | Why |
|---|---|---|
| `max_p2mr_tree_depth` | 32 | BIP-360 caps at 128; 32 is generous for real trees |
| `max_commitment_leaf_size` | 256 B | commitment payloads are ≤127 B (opret) / 59 B (p2mr-ret) |
| `max_control_block_size` | 1025 B | `1 + 32*depth` |
| `max_witness_size` | 16 KB | Dilithium5 sig (4627) + pk (2592) + script + control, headroom |
| `max_candidate_spends_per_seal` | 8 | reject "many candidate closing txs" DoS |
| `max_scan_window` | 64 | bound tx-output / leaf scans |
| `max_resolver_time_ms` | 5000 | wall-clock per resolve/verify |

Enforced in: `SealResolver::resolve`, `verify_commitment_in_outputs_bounded`,
`verify_p2mr_ret_bounded`, `CommitmentPayload::scan`, via `BudgetGuard`.

## Benchmark targets (`rgb-pq-bench`)

Run: `cargo test -p rgb-pq-bench --release -- --nocapture`

| Target | Measures |
|---|---|
| `bench_p2mr_leaf_verify` | Tapleaf hash |
| `bench_p2mr_ret_commitment_verify` | full P2MR-ret tree + proof verify |
| `bench_dilithium_verify` | PQ witness size-budget check |
| `bench_resolve_closed_valid` | resolver happy-path latency |
| `bench_resolve_closed_invalid` | resolver rejection latency |
| `bench_indexer_reorg_rollback` | indexer rollback latency |
| `bench_full_transfer_verify` | opret + p2mr-ret combined verify |

Every benchmark asserts it completes within the resolver DoS budget.

## Release-report language

> P2MR-ret adds one script-tree commitment proof over OPRET.
> PQ ownership adds larger witness/signature material.
> The implementation enforces depth/size/time bounds and benchmarks verifier
> latency separately from confirmation latency.
