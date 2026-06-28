//! Typed error hierarchy for RGB-PQ.
//!
//! Security-sensitive failures are never stringly typed. Each variant names the
//! exact invariant that was violated so callers (and tests) can match on it.

use core::fmt;

/// Top-level RGB-PQ error. Aggregates every subsystem's typed error.
#[derive(Debug, thiserror::Error)]
pub enum RgbPqError {
    /// A seal-level failure (encoding, parsing, validation).
    #[error(transparent)]
    Seal(#[from] SealError),
    /// A seal-state resolution failure (open/closed/unknown).
    #[error(transparent)]
    SealState(#[from] SealStateError),
    /// A commitment-binding failure.
    #[error(transparent)]
    Commitment(#[from] CommitmentError),
    /// A chain-backend failure (RPC, indexer, inclusion proof).
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// A raw RPC-layer failure (convenience, equivalent to Resolve(Rpc(...))).
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// An RGB consensus validation failure.
    #[error("RGB validation failure: {0}")]
    RgbValidation(String),
    /// An internal invariant was violated. Always a bug.
    #[error("internal invariant violation: {0}")]
    Invariant(String),
}

// =========================================================================
// Chain / network confusion
// =========================================================================

/// Confusion between an unsupported chain and a supported one.
///
/// Captures the exact wrong-chain categories the protocol must reject:
/// Bitcoin mainnet/testnet/signet/regtest, ordinary Taproot/P2TR, ordinary RGB
/// Bitcoin seals, non-P2MR BTQ outputs, and unknown chain ids.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainConfusion {
    /// The chain id is not one of the supported BTQ chains.
    #[error("unsupported chain id: {0}")]
    UnsupportedChain(String),
    /// The backend is on the wrong network (e.g. testnet while regtest wanted).
    #[error("wrong network: expected {expected}, got {actual}")]
    WrongNetwork {
        /// The chain the caller expected.
        expected: String,
        /// The chain the backend actually reported.
        actual: String,
    },
    /// A Bitcoin mainnet object was supplied. Mainnet is explicitly unsupported.
    #[error("bitcoin mainnet is not supported by RGB-PQ")]
    BitcoinMainnet,
    /// A Bitcoin testnet/signet/regtest object was supplied (not BTQ).
    #[error("non-BTQ bitcoin chain '{0}' is not a BTQ P2MR chain")]
    NonBtqBitcoin(String),
    /// A P2TR / ordinary Taproot output was supplied where P2MR is required.
    #[error("ordinary taproot/P2TR output is not a P2MR output")]
    OrdinaryTaproot,
    /// An ordinary RGB Bitcoin seal was supplied where a BTQ P2MR seal is
    /// required.
    #[error("ordinary RGB bitcoin seal is not a BTQ P2MR seal")]
    OrdinaryRgbSeal,
    /// A non-P2MR BTQ output was supplied.
    #[error("non-P2MR BTQ output")]
    NonP2mrBtqOutput,
    /// The chain id was not recognised at all.
    #[error("unknown chain id")]
    UnknownChainId,
}

// =========================================================================
// Ownership / PQ algorithm
// =========================================================================

/// Failures relating to the post-quantum ownership algorithm.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnerAlgoError {
    /// A secp256k1 ownership path was supplied where post-quantum ownership is
    /// required. This is never silently downgraded.
    #[error("secp256k1 ownership is not post-quantum; PQ ownership required")]
    Secp256k1NotAllowed,
    /// The PQ algorithm is not supported.
    #[error("unsupported PQ algorithm id: {0}")]
    UnsupportedAlgo(u8),
    /// The PQ algorithm is supported only behind a feature gate that is off.
    #[error("PQ algorithm '{0}' requires a feature gate that is not enabled")]
    FeatureGated(String),
}

// =========================================================================
// Malformed seal / output
// =========================================================================

/// A seal or P2MR output was malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MalformedSealError {
    /// The binary encoding could not be parsed.
    #[error("malformed seal encoding: {0}")]
    BadEncoding(String),
    /// The seal version is unknown.
    #[error("unknown seal version: {0}")]
    UnknownVersion(u8),
    /// The P2MR output is malformed (e.g. wrong witness version / size).
    #[error("malformed P2MR output: {0}")]
    BadP2mrOutput(String),
    /// The bech32m / textual representation could not be parsed.
    #[error("malformed textual seal: {0}")]
    BadText(String),
    /// A field had an invalid length.
    #[error("invalid field length for '{field}': expected {expected}, got {actual}")]
    BadLength {
        /// Field name.
        field: &'static str,
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },
}

// =========================================================================
// Seal validation (root / leaf / algo / chain)
// =========================================================================

/// A structurally-valid seal failed a semantic check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// A chain/network confusion. See [`ChainConfusion`].
    #[error(transparent)]
    Chain(#[from] ChainConfusion),
    /// An ownership-algorithm failure. See [`OwnerAlgoError`].
    #[error(transparent)]
    OwnerAlgo(#[from] OwnerAlgoError),
    /// The seal was malformed. See [`MalformedSealError`].
    #[error(transparent)]
    Malformed(#[from] MalformedSealError),
    /// The on-chain P2MR root does not match the seal's expected root.
    #[error("wrong P2MR root: expected {expected}, got {actual}")]
    WrongP2mrRoot {
        /// Expected 32-byte root (hex).
        expected: String,
        /// Actual 32-byte root (hex).
        actual: String,
    },
    /// The on-chain script leaf hash does not match the seal's expected leaf.
    #[error("wrong script leaf hash: expected {expected}, got {actual}")]
    WrongScriptLeaf {
        /// Expected 32-byte leaf hash (hex).
        expected: String,
        /// Actual 32-byte leaf hash (hex).
        actual: String,
    },
}

// =========================================================================
// Commitment binding
// =========================================================================

/// A failure while binding or verifying an RGB transition commitment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitmentError {
    /// The closing transaction carries no commitment output.
    #[error("missing commitment in transaction {0}")]
    Missing(String),
    /// The commitment is present but malformed.
    #[error("malformed commitment: {0}")]
    Malformed(String),
    /// Two conflicting commitments were found for the same seal.
    #[error("duplicate conflicting commitments for seal {0}")]
    Duplicate(String),
    /// The commitment is bound to the wrong chain.
    #[error("wrong-chain commitment")]
    WrongChain,
    /// The commitment is bound to the wrong seal.
    #[error("wrong-seal commitment")]
    WrongSeal,
    /// The RGB transition id/digest does not match the commitment.
    #[error("commitment does not match RGB transition: expected {expected}, got {actual}")]
    TransitionMismatch {
        /// Expected digest (hex).
        expected: String,
        /// Actual digest (hex).
        actual: String,
    },
}

// =========================================================================
// Resolution / chain backend
// =========================================================================

/// A failure from the chain backend (RPC, indexer, inclusion proof).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The transaction is missing from the backend.
    #[error("missing transaction {0}")]
    MissingTx(String),
    /// The output is missing / does not exist.
    #[error("missing output {0}")]
    MissingOutput(String),
    /// No inclusion proof could be produced.
    #[error("missing inclusion proof for {0}")]
    MissingInclusionProof(String),
    /// The transaction is unconfirmed.
    #[error("unconfirmed transaction {0}")]
    Unconfirmed(String),
    /// The transaction does not have enough confirmations.
    #[error("insufficient confirmations for {txid}: have {have}, need {need}")]
    InsufficientConfirmations {
        /// Transaction id (hex).
        txid: String,
        /// Current depth.
        have: u32,
        /// Required depth.
        need: u32,
    },
    /// A conflicting spend of the watched outpoint was detected.
    #[error("conflicting spend of {0}")]
    ConflictingSpend(String),
    /// A chain reorg was detected.
    #[error("reorg detected at height {height} (old tip {old_tip}, new tip {new_tip})")]
    Reorg {
        /// Block height at which the reorg forked.
        height: u32,
        /// Previous tip hash (hex).
        old_tip: String,
        /// New tip hash (hex).
        new_tip: String,
    },
    /// The RPC layer failed.
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// The indexer is unavailable.
    #[error(transparent)]
    Index(#[from] IndexError),
    /// The BTQ node is unavailable.
    #[error(transparent)]
    NodeUnavailable(#[from] NodeUnavailable),
    /// A requested BTQ feature is not supported by the connected node.
    #[error(transparent)]
    Feature(#[from] BtqFeature),
}

/// The BTQ node could not be reached.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("BTQ node unavailable: {0}")]
pub struct NodeUnavailable(pub String);

/// A BTQ feature the adapter needs is not supported by the connected node.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BtqFeature {
    /// The node does not support P2MR outputs.
    #[error("BTQ feature unavailable: P2MR not supported by node")]
    P2mrUnsupported,
    /// The node does not support Dilithium signatures.
    #[error("BTQ feature unavailable: Dilithium not supported by node")]
    DilithiumUnsupported,
    /// The node does not support the requested RPC method.
    #[error("BTQ feature unavailable: RPC method '{0}' not supported")]
    RpcMethodUnsupported(String),
}

/// A generic "unsupported feature" wrapper used at API boundaries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnsupportedFeature {
    /// An unsupported seal version.
    #[error("unsupported seal version: {0}")]
    SealVersion(u8),
    /// An unsupported commitment locator kind.
    #[error("unsupported commitment locator: {0}")]
    CommitmentLocator(String),
}

/// An RPC-layer failure. Never panics; never logs secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    /// The request timed out.
    #[error("RPC timeout after {0}s contacting {1}")]
    Timeout(u64, String),
    /// A transport error (connection refused, TLS, etc.).
    #[error("RPC transport error contacting {endpoint}: {detail}")]
    Transport {
        /// The endpoint URL (without credentials).
        endpoint: String,
        /// Error detail (no secrets).
        detail: String,
    },
    /// The node returned an HTTP error status.
    #[error("RPC HTTP {status} from {endpoint}: {detail}")]
    HttpStatus {
        /// HTTP status code.
        status: u16,
        /// Endpoint URL (without credentials).
        endpoint: String,
        /// Error detail.
        detail: String,
    },
    /// The node returned an RPC-level error object.
    #[error("RPC error {code} from {endpoint}: {message}")]
    RpcLevel {
        /// JSON-RPC error code.
        code: i64,
        /// Endpoint URL (without credentials).
        endpoint: String,
        /// Error message.
        message: String,
    },
    /// The response could not be deserialised.
    #[error("RPC deserialisation error from {0}: {1}")]
    Decode(String, String),
    /// Authentication failed.
    #[error("RPC authentication failed for {0}")]
    Auth(String),
    /// Wrong network reported by the node.
    #[error(transparent)]
    WrongNetwork(#[from] ChainConfusion),
}

/// An indexer-layer failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IndexError {
    /// The indexer is not running / not initialised.
    #[error("indexer unavailable: {0}")]
    Unavailable(String),
    /// A persistence (database) error.
    #[error("indexer persistence error: {0}")]
    Persistence(String),
    /// An inconsistent indexer state was observed.
    #[error("indexer inconsistency: {0}")]
    Inconsistent(String),
}

// =========================================================================
// Seal state
// =========================================================================

/// Why a closed seal was considered invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidSealCloseReason {
    /// The spending transaction does not spend the watched outpoint.
    #[error("spend does not consume the watched outpoint")]
    NotSpentByTx,
    /// The spend was not via the expected P2MR / Dilithium ownership path.
    #[error("spend did not use the expected P2MR/Dilithium ownership path")]
    WrongOwnershipPath,
    /// The P2MR root on the spent output did not match.
    #[error(transparent)]
    WrongRoot(#[from] SealError),
    /// The commitment was missing or invalid.
    #[error(transparent)]
    Commitment(#[from] CommitmentError),
    /// A chain/backend error occurred while verifying the close.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
}

/// Why a seal's state is unknown.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnknownSealStateReason {
    /// The outpoint does not exist on chain.
    #[error("outpoint does not exist")]
    OutpointMissing,
    /// The backend could not answer.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
}

/// A seal-state resolution failure surfaced as an error (vs. the informational
/// [`crate::SealState`] enum used by the resolver).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealStateError {
    /// A chain/backend failure.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// A seal validation failure.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// The seal is closed but invalid.
    #[error(transparent)]
    InvalidClose(#[from] InvalidSealCloseReason),
}

// =========================================================================
// Convenience direct conversions from leaf errors to RgbPqError.
//
// The leaf error types (ChainConfusion, OwnerAlgoError, MalformedSealError,
// UnsupportedFeature) are used across many crates. Routing them through
// SealError every time is verbose; these impls let `.into()` / `?` produce a
// RgbPqError uniformly while still preserving the full typed structure.
// =========================================================================

impl From<ChainConfusion> for RgbPqError {
    fn from(e: ChainConfusion) -> Self {
        RgbPqError::Seal(SealError::from(e))
    }
}

impl From<OwnerAlgoError> for RgbPqError {
    fn from(e: OwnerAlgoError) -> Self {
        RgbPqError::Seal(SealError::from(e))
    }
}

impl From<MalformedSealError> for RgbPqError {
    fn from(e: MalformedSealError) -> Self {
        RgbPqError::Seal(SealError::from(e))
    }
}

impl From<UnsupportedFeature> for RgbPqError {
    fn from(e: UnsupportedFeature) -> Self {
        match e {
            UnsupportedFeature::SealVersion(v) => {
                RgbPqError::Seal(SealError::Malformed(MalformedSealError::UnknownVersion(v)))
            }
            other => RgbPqError::Invariant(format!("unsupported: {other}")),
        }
    }
}

impl From<InvalidSealCloseReason> for RgbPqError {
    fn from(e: InvalidSealCloseReason) -> Self {
        RgbPqError::SealState(SealStateError::InvalidClose(e))
    }
}

#[cfg(test)]
mod tests {
    use crate::RgbPqResult;
    use super::*;

    #[test]
    fn errors_are_not_stringly_typed() {
        // Every variant used in security-critical paths is a distinct type or
        // variant, not a String. This test guards against regressions to a
        // single String error type.
        let e = RgbPqError::from(SealError::from(ChainConfusion::BitcoinMainnet));
        let s = format!("{e}");
        assert!(s.contains("mainnet"));
        let _ = OwnerAlgoError::Secp256k1NotAllowed;
        let _ = ChainConfusion::OrdinaryTaproot;
        let _ = ChainConfusion::OrdinaryRgbSeal;
    }

    #[test]
    fn from_chaining_compiles() {
        // RpcError -> RgbPqError via the direct From<RpcError> impl.
        let r: RgbPqResult<()> =
            Err(RpcError::Timeout(5, "x".into())).map_err(RgbPqError::from);
        // RpcError -> ResolveError -> SealStateError -> RgbPqError chain still works.
        let r2: RgbPqResult<()> =
            Err(RpcError::Timeout(5, "x".into()))
                .map_err(ResolveError::from)
                .map_err(SealStateError::from)
                .map_err(RgbPqError::from);
        assert!(matches!(r, Err(RgbPqError::Rpc(RpcError::Timeout(5, _)))));
        assert!(matches!(
            r2,
            Err(RgbPqError::SealState(SealStateError::Resolve(ResolveError::Rpc(
                RpcError::Timeout(5, _)
            ))))
        ));
    }
}
