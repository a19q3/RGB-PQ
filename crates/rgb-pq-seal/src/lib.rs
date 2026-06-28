//! RGB-PQ canonical BTQ P2MR single-use seal.
//!
//! This crate defines [`BtqP2mrSeal`], the consensus-safe, serialisable seal
//! type that represents a BTQ P2MR output owned by a post-quantum Dilithium
//! leaf, used as an RGB single-use seal.
//!
//! See `ARCHITECTURE.md` §3.2 for how this maps onto RGB's own `GraphSeal`.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

#[cfg(test)]
mod property;
pub mod seal;
pub mod types;
#[cfg(test)]
mod vectors;

pub use seal::{BtqP2mrSeal, P2mrRoot, ScriptLeafHash, BIN_MAGIC, SEAL_HRP};
pub use types::{
    BtqChainId, BtqOutpoint, BtqTxid, CommitmentLocator, ConfirmationPolicy, PqSigAlgo, SealVersion,
};

/// The domain-tag bytes embedded in the binary encoding. Mirrors
/// [`rgb_pq_core::DOMAIN_TAG`] so that the seal bytes are self-identifying.
pub const DOMAIN_TAG_BYTES: &[u8] = rgb_pq_core::DOMAIN_TAG;
