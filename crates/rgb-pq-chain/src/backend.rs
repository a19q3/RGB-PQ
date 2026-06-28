//! The BTQ chain backend trait (Component 3) and its supporting data types.
//!
//! This is the abstraction every RGB-PQ component talks to when it needs chain
//! data. The trait is intentionally narrow and distinguished: every method
//! returns a typed [`rgb_pq_core::ResolveError`] so callers can tell missing
//! transaction, missing output, unconfirmed, spent, conflicting spend, reorg
//! and backend-unavailable apart — never a bare `String`.

use rgb_pq_core::{BtqFeature, NodeUnavailable, ResolveError, RgbPqResult};
use rgb_pq_seal::{BtqChainId, BtqOutpoint};

/// A chain tip (best block).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainTip {
    /// Best block height.
    pub height: u32,
    /// Best block hash (display hex).
    pub hash: String,
}

/// Status of a transaction on the backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxStatus {
    /// The tx is confirmed in a block.
    Confirmed {
        /// Block height.
        height: u32,
        /// Block hash (display hex).
        block_hash: String,
        /// Number of confirmations (depth from the tip).
        confirmations: u32,
        /// Block timestamp (median-time-past), as reported by the node.
        time: i64,
    },
    /// The tx is in the mempool (unconfirmed).
    Unconfirmed,
}

impl TxStatus {
    /// Confirmations depth (0 if unconfirmed).
    pub fn confirmations(&self) -> u32 {
        match self {
            TxStatus::Confirmed { confirmations, .. } => *confirmations,
            TxStatus::Unconfirmed => 0,
        }
    }
}

/// A fetched transaction (raw hex + decoded status).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtqTx {
    /// The transaction id (display hex).
    pub txid: String,
    /// Raw transaction bytes (hex-encoded by the RPC layer; stored decoded here).
    pub raw: Vec<u8>,
    /// Status.
    pub status: TxStatus,
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtqTxOut {
    /// The outpoint.
    pub outpoint: BtqOutpoint,
    /// The value in satoshis.
    pub value: u64,
    /// The scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
    /// Whether this output has been spent.
    pub spent: bool,
}

/// A Merkle inclusion proof that a tx is in a block (Bitcoin Core
/// `gettxoutproof` format: hex).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtqInclusionProof {
    /// The txid this proof covers.
    pub txid: String,
    /// The block hash anchoring the proof.
    pub block_hash: String,
    /// The hex-encoded partial merkle tree proof.
    pub proof_hex: String,
}

/// The chain backend trait.
///
/// Implementations must distinguish every failure mode listed in the brief
/// (missing tx, missing output, unconfirmed, confirmed, spent, unspent,
/// conflicting spend, reorg risk, backend unavailable, node/network mismatch,
/// unsupported BTQ feature).
pub trait BtqChainBackend {
    /// The chain this backend is configured for.
    fn network_id(&self) -> BtqChainId;

    /// Current best block.
    fn current_tip(&self) -> RgbPqResult<ChainTip>;

    /// Fetch a transaction by id.
    ///
    /// Returns `Err(MissingTx)` if absent, never panics.
    fn get_tx(&self, txid: &str) -> RgbPqResult<Option<BtqTx>>;

    /// Fetch the confirmation status of a tx.
    fn get_tx_status(&self, txid: &str) -> RgbPqResult<TxStatus>;

    /// Fetch a specific output. Returns `None` if the outpoint does not exist.
    fn get_output(&self, outpoint: &BtqOutpoint) -> RgbPqResult<Option<BtqTxOut>>;

    /// Fetch the transaction that spends `outpoint`, if any.
    fn get_spending_tx(&self, outpoint: &BtqOutpoint) -> RgbPqResult<Option<BtqTx>>;

    /// Prove that a tx is included in a block (Merkle proof).
    fn prove_tx_inclusion(&self, txid: &str) -> RgbPqResult<BtqInclusionProof>;

    /// Confirmation depth of a tx (`None` if unconfirmed or unknown).
    fn confirmation_depth(&self, txid: &str) -> RgbPqResult<Option<u32>>;

    /// Broadcast a raw transaction, if the backend supports it.
    fn broadcast_tx(&self, _raw_hex: &str) -> RgbPqResult<String> {
        Err(ResolveError::Feature(BtqFeature::RpcMethodUnsupported("broadcast_tx".into())).into())
    }
}

/// Sanity-check helper: turn a connection failure into a typed
/// [`NodeUnavailable`].
pub fn node_unavailable(detail: impl Into<String>) -> ResolveError {
    ResolveError::NodeUnavailable(NodeUnavailable(detail.into()))
}
