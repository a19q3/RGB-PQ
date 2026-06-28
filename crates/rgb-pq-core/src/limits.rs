//! Verification budget / DoS-defence limits.
//!
//! RGB-PQ verifies client-supplied data (consignments, P2MR trees, witnesses,
//! commitment proofs, candidate spends). A malicious peer can hand the verifier
//! huge P2MR trees, malformed leaves, repeated commitments, or many candidate
//! closing txs to burn CPU. These limits make that unprofitable: every
//! verification path enforces them and **fails closed** (returns `DoSError` /
//! `Unknown` / `ClosedInvalid`, never `ClosedValid`) when a limit is exceeded.
//!
//! ## Verification latency vs finality latency (kept separate)
//!
//! These limits bound **verification latency** (CPU / parsing / proof-checking
//! time) — the work the verifier itself does. They are deliberately distinct
//! from **finality latency** (waiting for confirmations / reorg safety), which
//! is governed by [`crate`]'s `ConfirmationPolicy`. Never conflate a vague
//! "timeout" with confirmation depth.

/// A verification path exceeded a DoS-defence limit.
///
/// The resolver / verifier must translate this into a **fail-closed** result
/// (`SealState::Unknown` or `ClosedInvalid`, never `ClosedValid`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DoSError {
    /// A P2MR script tree / Merkle path exceeded the max depth.
    #[error("P2MR tree depth {depth} exceeds max {max}")]
    TreeDepthExceeded {
        /// Observed depth.
        depth: u32,
        /// Configured maximum.
        max: u32,
    },
    /// A commitment leaf (or its payload) exceeded the max size.
    #[error("commitment leaf size {size} exceeds max {max}")]
    LeafSizeExceeded {
        /// Observed size in bytes.
        size: usize,
        /// Configured maximum.
        max: usize,
    },
    /// A control block exceeded the max size (depth-derived).
    #[error("control block size {size} exceeds max {max}")]
    ControlBlockSizeExceeded {
        /// Observed size in bytes.
        size: usize,
        /// Configured maximum.
        max: usize,
    },
    /// A witness exceeded the max total size.
    #[error("witness size {size} exceeds max {max}")]
    WitnessSizeExceeded {
        /// Observed size in bytes.
        size: usize,
        /// Configured maximum.
        max: usize,
    },
    /// Too many candidate spends were presented for one seal.
    #[error("{count} candidate spends for one seal exceed max {max}")]
    TooManyCandidateSpends {
        /// Observed count.
        count: usize,
        /// Configured maximum.
        max: usize,
    },
    /// A scan window (tx outputs / indexer rows) exceeded the max.
    #[error("scan window {count} exceeds max {max}")]
    ScanWindowExceeded {
        /// Observed count.
        count: usize,
        /// Configured maximum.
        max: usize,
    },
    /// A bounded operation took longer than the configured wall-clock budget.
    #[error("resolver time {elapsed_ms}ms exceeds max {max_ms}ms")]
    ResolverTimeExceeded {
        /// Elapsed milliseconds.
        elapsed_ms: u128,
        /// Configured maximum.
        max_ms: u128,
    },
}

impl From<DoSError> for crate::RgbPqError {
    fn from(e: DoSError) -> Self {
        crate::RgbPqError::Invariant(format!("DoS limit: {e}"))
    }
}

/// The set of DoS-defence limits used across all RGB-PQ verification paths.
///
/// Defaults are conservative for a single-seal local/CI verifier. Production
/// deployments with higher throughput may tune them, but should never disable
/// them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyLimits {
    /// Max P2MR script-tree / Merkle-path depth (BIP-360 caps at 128).
    pub max_p2mr_tree_depth: u32,
    /// Max commitment-leaf payload size (bytes).
    pub max_commitment_leaf_size: usize,
    /// Max P2MR control-block size (bytes). `1 + 32*depth`.
    pub max_control_block_size: usize,
    /// Max total witness size per input (bytes). PQ signatures are large:
    /// Dilithium2 sig ≈ 2420 B + pk 1312 B; Dilithium5 sig ≈ 4627 B.
    pub max_witness_size: usize,
    /// Max candidate closing txs considered for a single seal.
    pub max_candidate_spends_per_seal: usize,
    /// Max items scanned when looking for a commitment (tx outputs / leaves).
    pub max_scan_window: usize,
    /// Max wall-clock milliseconds for a single resolve/verify operation.
    pub max_resolver_time_ms: u128,
}

impl VerifyLimits {
    /// Conservative defaults for a local/CI verifier.
    pub const DEFAULT: Self = Self {
        max_p2mr_tree_depth: 32,
        max_commitment_leaf_size: 256,
        // 1 + 32 * 32 (depth 32) = 1025
        max_control_block_size: 1 + 32 * 32,
        // Dilithium5 sig (4627) + pk (2592) + script + control, with headroom.
        max_witness_size: 16 * 1024,
        max_candidate_spends_per_seal: 8,
        max_scan_window: 64,
        max_resolver_time_ms: 5_000,
    };

    /// Check a tree depth against the limit.
    pub fn check_tree_depth(&self, depth: u32) -> Result<(), DoSError> {
        if depth > self.max_p2mr_tree_depth {
            Err(DoSError::TreeDepthExceeded {
                depth,
                max: self.max_p2mr_tree_depth,
            })
        } else {
            Ok(())
        }
    }

    /// Check a leaf payload size against the limit.
    pub fn check_leaf_size(&self, size: usize) -> Result<(), DoSError> {
        if size > self.max_commitment_leaf_size {
            Err(DoSError::LeafSizeExceeded {
                size,
                max: self.max_commitment_leaf_size,
            })
        } else {
            Ok(())
        }
    }

    /// Check a control-block size against the limit.
    pub fn check_control_block_size(&self, size: usize) -> Result<(), DoSError> {
        if size > self.max_control_block_size {
            Err(DoSError::ControlBlockSizeExceeded {
                size,
                max: self.max_control_block_size,
            })
        } else {
            Ok(())
        }
    }

    /// Check a witness size against the limit.
    pub fn check_witness_size(&self, size: usize) -> Result<(), DoSError> {
        if size > self.max_witness_size {
            Err(DoSError::WitnessSizeExceeded {
                size,
                max: self.max_witness_size,
            })
        } else {
            Ok(())
        }
    }

    /// Check the number of candidate spends against the limit.
    pub fn check_candidate_spends(&self, count: usize) -> Result<(), DoSError> {
        if count > self.max_candidate_spends_per_seal {
            Err(DoSError::TooManyCandidateSpends {
                count,
                max: self.max_candidate_spends_per_seal,
            })
        } else {
            Ok(())
        }
    }

    /// Check a scan window size against the limit.
    pub fn check_scan_window(&self, count: usize) -> Result<(), DoSError> {
        if count > self.max_scan_window {
            Err(DoSError::ScanWindowExceeded {
                count,
                max: self.max_scan_window,
            })
        } else {
            Ok(())
        }
    }

    /// Check an elapsed time against the limit.
    pub fn check_resolver_time(&self, elapsed_ms: u128) -> Result<(), DoSError> {
        if elapsed_ms > self.max_resolver_time_ms {
            Err(DoSError::ResolverTimeExceeded {
                elapsed_ms,
                max_ms: self.max_resolver_time_ms,
            })
        } else {
            Ok(())
        }
    }
}

impl Default for VerifyLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A small wall-clock budget guard. Call [`BudgetGuard::check`] periodically
/// inside a long verification loop; it fails closed if the budget is exceeded.
pub struct BudgetGuard {
    start: std::time::Instant,
    max_ms: u128,
}

impl BudgetGuard {
    /// Start a guard with a max duration (ms).
    pub fn start(max_ms: u128) -> Self {
        Self {
            start: std::time::Instant::now(),
            max_ms,
        }
    }

    /// Returns `Err(ResolverTimeExceeded)` if the budget has been spent.
    pub fn check(&self) -> Result<(), DoSError> {
        let elapsed = self.start.elapsed().as_millis();
        if elapsed > self.max_ms {
            Err(DoSError::ResolverTimeExceeded {
                elapsed_ms: elapsed,
                max_ms: self.max_ms,
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let l = VerifyLimits::DEFAULT;
        assert!(l.max_p2mr_tree_depth >= 1 && l.max_p2mr_tree_depth <= 128);
        assert!(l.max_commitment_leaf_size >= 127); // opret payload is 127
        assert!(l.max_witness_size >= 4627 + 2592); // Dilithium5 worst case
    }

    #[test]
    fn depth_limit_rejects() {
        let l = VerifyLimits::DEFAULT;
        assert!(l.check_tree_depth(5).is_ok());
        assert!(l.check_tree_depth(10_000).is_err());
    }

    #[test]
    fn leaf_size_limit_rejects() {
        let l = VerifyLimits::DEFAULT;
        assert!(l.check_leaf_size(127).is_ok());
        assert!(l.check_leaf_size(10_000_000).is_err());
    }

    #[test]
    fn witness_size_limit_rejects() {
        let l = VerifyLimits::DEFAULT;
        // Dilithium5 worst case fits.
        assert!(l.check_witness_size(4627 + 2592 + 1024).is_ok());
        // 10MB witness rejected.
        assert!(l.check_witness_size(10 * 1024 * 1024).is_err());
    }

    #[test]
    fn candidate_spends_limit_rejects() {
        let l = VerifyLimits::DEFAULT;
        assert!(l.check_candidate_spends(1).is_ok());
        assert!(l.check_candidate_spends(1_000_000).is_err());
    }

    #[test]
    fn budget_guard_expires() {
        let g = BudgetGuard::start(0); // 0ms budget
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(g.check().is_err());
    }

    #[test]
    fn budget_guard_within_budget() {
        let g = BudgetGuard::start(60_000);
        assert!(g.check().is_ok());
    }
}
