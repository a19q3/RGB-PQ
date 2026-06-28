//! RGB-PQ verification-latency microbenchmarks.
//!
//! These benchmarks measure **verification latency** (CPU / parsing /
//! proof-checking time) — the work the verifier itself does — deliberately
//! kept separate from **finality latency** (waiting for confirmations / reorg
//! safety), which is governed by `ConfirmationPolicy`.
//!
//! They are dependency-light (no `criterion`) and run under `cargo test` so
//! they are CI-friendly. Each returns a [`BenchResult`] with the per-iteration
//! latency; run `cargo test -p rgb-pq-bench --release -- --nocapture` to see
//! the report.
//!
//! ## Benchmark targets
//!
//! | Target | What it measures |
//! |---|---|
//! | `bench_p2mr_leaf_verify` | Tapleaf hash computation |
//! | `bench_p2mr_ret_commitment_verify` | full P2MR-ret tree + proof verify |
//! | `bench_dilithium_verify` | (placeholder) PQ signature material handling |
//! | `bench_resolve_closed_valid` | resolver happy-path latency |
//! | `bench_resolve_closed_invalid` | resolver rejection latency |
//! | `bench_indexer_reorg_rollback` | indexer rollback latency |
//! | `bench_full_transfer_verify` | opret + p2mr-ret combined verify |

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

use std::time::{Duration, Instant};

use rgb_pq_chain::{BtqChainBackend, BtqInclusionProof, BtqTx, BtqTxOut, ChainTip, TxStatus};
use rgb_pq_commit::{
    build_p2mr_ret_tree_for_seal, compute_tapleaf_hash, verify_p2mr_ret, MpcCommitment,
};
use rgb_pq_core::{RgbPqResult, VerifyLimits};
use rgb_pq_resolver::SealResolver;
use rgb_pq_seal::{
    BtqChainId, BtqOutpoint, BtqP2mrSeal, BtqTxid, CommitmentLocator, ConfirmationPolicy, PqSigAlgo,
};

/// A single benchmark result.
#[derive(Clone, Debug)]
pub struct BenchResult {
    /// Benchmark name.
    pub name: &'static str,
    /// Number of iterations measured.
    pub iters: u32,
    /// Mean latency per iteration.
    pub mean: Duration,
    /// Minimum latency observed.
    pub min: Duration,
    /// Maximum latency observed.
    pub max: Duration,
}

impl BenchResult {
    /// Run a closure `iters` times and collect latency statistics.
    pub fn run(name: &'static str, iters: u32, mut f: impl FnMut()) -> Self {
        let mut durations = Vec::with_capacity(iters as usize);
        for _ in 0..iters {
            let start = Instant::now();
            f();
            durations.push(start.elapsed());
        }
        let total: Duration = durations.iter().sum();
        let mean = total / iters;
        let min = durations.iter().copied().min().unwrap_or_default();
        let max = durations.iter().copied().max().unwrap_or_default();
        Self {
            name,
            iters,
            mean,
            min,
            max,
        }
    }

    /// Pretty-print the result.
    pub fn report(&self) {
        println!(
            "{:<38} iters={:>5}  mean={:>10.3?}  min={:>10.3?}  max={:>10.3?}",
            self.name, self.iters, self.mean, self.min, self.max
        );
    }
}

/// A sample seal + mpc for benchmarking.
pub fn bench_seal() -> (BtqP2mrSeal, MpcCommitment) {
    let seal = BtqP2mrSeal::new(
        BtqChainId::BitcoinQuantumRegtest,
        BtqOutpoint::new(BtqTxid::from_bytes([0x11; 32]), 0),
        [0x22; 32],
        compute_tapleaf_hash(0xc0, &[0x51]),
        PqSigAlgo::Dilithium2,
        CommitmentLocator::P2mrRetLeaf,
        ConfirmationPolicy::OneConf,
    );
    (seal, [0xa5; 32])
}

/// bench_p2mr_leaf_verify: Tapleaf hash computation.
pub fn bench_p2mr_leaf_verify(iters: u32) -> BenchResult {
    let leaf = vec![0x51u8];
    BenchResult::run("bench_p2mr_leaf_verify", iters, || {
        let _ = compute_tapleaf_hash(0xc0, &leaf);
    })
}

/// bench_p2mr_ret_commitment_verify: full P2MR-ret tree + proof verify.
pub fn bench_p2mr_ret_commitment_verify(iters: u32) -> BenchResult {
    let (seal, mpc) = bench_seal();
    let pq_leaf = vec![0x51u8];
    // Precompute the tree to set the seal root, so verify succeeds.
    let tree = build_p2mr_ret_tree_for_seal(seal.chain_id, mpc, &pq_leaf);
    let mut seal = seal;
    seal.p2mr_root = tree.root;
    BenchResult::run("bench_p2mr_ret_commitment_verify", iters, || {
        let _ = verify_p2mr_ret(&seal, mpc, &pq_leaf);
    })
}

/// bench_dilithium_verify: PQ signature material handling (size accounting).
///
/// This measures the DoS-limit witness-size check + material sizing for a
/// Dilithium2-sized witness, not a real Dilithium verify (which lives in the
/// node). It documents that PQ witnesses are the dominant size variable.
pub fn bench_dilithium_verify(iters: u32) -> BenchResult {
    let limits = VerifyLimits::DEFAULT;
    // Dilithium2: sig 2420 + pk 1312 + script + control ≈ 4KB.
    let witness = vec![0u8; 2420 + 1312 + 256];
    BenchResult::run("bench_dilithium_verify (size budget)", iters, || {
        let _ = limits.check_witness_size(witness.len());
    })
}

/// A fake backend for resolver benchmarks.
pub struct BenchBackend {
    chain: BtqChainId,
    out: Option<BtqTxOut>,
    spend: Option<BtqTx>,
}

impl BtqChainBackend for BenchBackend {
    fn network_id(&self) -> BtqChainId {
        self.chain
    }
    fn current_tip(&self) -> RgbPqResult<ChainTip> {
        Ok(ChainTip {
            height: 200,
            hash: "deadbeef".into(),
        })
    }
    fn get_tx(&self, _txid: &str) -> RgbPqResult<Option<BtqTx>> {
        Ok(self.spend.clone())
    }
    fn get_tx_status(&self, _txid: &str) -> RgbPqResult<TxStatus> {
        Ok(TxStatus::Confirmed {
            height: 100,
            block_hash: "ab".into(),
            confirmations: 6,
            time: 0,
        })
    }
    fn get_output(&self, _o: &BtqOutpoint) -> RgbPqResult<Option<BtqTxOut>> {
        Ok(self.out.clone())
    }
    fn get_spending_tx(&self, _o: &BtqOutpoint) -> RgbPqResult<Option<BtqTx>> {
        Ok(self.spend.clone())
    }
    fn prove_tx_inclusion(&self, _txid: &str) -> RgbPqResult<BtqInclusionProof> {
        Ok(BtqInclusionProof {
            txid: "01".into(),
            block_hash: "ab".into(),
            proof_hex: "00".into(),
        })
    }
    fn confirmation_depth(&self, _txid: &str) -> RgbPqResult<Option<u32>> {
        Ok(Some(6))
    }
}

/// bench_resolve_closed_valid: resolver happy-path latency.
pub fn bench_resolve_closed_valid(iters: u32) -> BenchResult {
    let (seal, _) = bench_seal();
    // Backend with an unspent output → OpenUnspent (happy path, no spend).
    let b = BenchBackend {
        chain: BtqChainId::BitcoinQuantumRegtest,
        out: Some(p2mr_out(&seal, false)),
        spend: None,
    };
    let r = SealResolver::new(&b);
    BenchResult::run("bench_resolve_closed_valid", iters, || {
        let _ = r.resolve(&seal);
    })
}

/// bench_resolve_closed_invalid: resolver rejection latency.
pub fn bench_resolve_closed_invalid(iters: u32) -> BenchResult {
    let (seal, _) = bench_seal();
    // Backend on the wrong chain → Unknown (rejection path).
    let b = BenchBackend {
        chain: BtqChainId::BitcoinQuantumTestnet,
        out: Some(p2mr_out(&seal, false)),
        spend: None,
    };
    let r = SealResolver::new(&b);
    BenchResult::run("bench_resolve_closed_invalid", iters, || {
        let _ = r.resolve(&seal);
    })
}

/// bench_indexer_reorg_rollback: indexer rollback latency.
pub fn bench_indexer_reorg_rollback(iters: u32) -> BenchResult {
    use rgb_pq_chain::{Indexer, MemIndexer};
    BenchResult::run("bench_indexer_reorg_rollback", iters, || {
        let mut idx = MemIndexer::new();
        idx.set_tip(ChainTip {
            height: 1000,
            hash: "h".into(),
        });
        let o = BtqOutpoint::new(BtqTxid::from_bytes([0xaa; 32]), 0);
        let _ = idx.watch(&o);
        let _ = idx.rollback(500);
    })
}

/// bench_full_transfer_verify: opret + p2mr-ret combined verify.
pub fn bench_full_transfer_verify(iters: u32) -> BenchResult {
    let (seal, mpc) = bench_seal();
    let pq_leaf = vec![0x51u8];
    let tree = build_p2mr_ret_tree_for_seal(seal.chain_id, mpc, &pq_leaf);
    let mut seal = seal;
    seal.p2mr_root = tree.root;
    BenchResult::run("bench_full_transfer_verify", iters, || {
        let _ = verify_p2mr_ret(&seal, mpc, &pq_leaf);
        let _ = seal.canonical_digest();
    })
}

/// Run the full suite and print a report. Returns all results.
pub fn run_suite(iters: u32) -> Vec<BenchResult> {
    let results = vec![
        bench_p2mr_leaf_verify(iters),
        bench_p2mr_ret_commitment_verify(iters),
        bench_dilithium_verify(iters),
        bench_resolve_closed_valid(iters),
        bench_resolve_closed_invalid(iters),
        bench_indexer_reorg_rollback(iters),
        bench_full_transfer_verify(iters),
    ];
    println!("\n=== RGB-PQ verification-latency benchmarks (separate from finality) ===");
    for r in &results {
        r.report();
    }
    println!();
    results
}

fn p2mr_out(seal: &BtqP2mrSeal, spent: bool) -> BtqTxOut {
    let mut spk = vec![0x52, 0x20];
    spk.extend_from_slice(&seal.p2mr_root);
    BtqTxOut {
        outpoint: seal.outpoint,
        value: 1000,
        script_pubkey: spk,
        spent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_suite_runs() {
        // Small iteration count for CI; use --release for real numbers.
        let results = run_suite(200);
        assert_eq!(results.len(), 7);
        // Every benchmark must complete in well under the DoS resolver budget.
        for r in &results {
            assert!(
                r.mean.as_millis() < VerifyLimits::DEFAULT.max_resolver_time_ms,
                "{} mean {}ms exceeds resolver budget",
                r.name,
                r.mean.as_millis()
            );
        }
    }
}
