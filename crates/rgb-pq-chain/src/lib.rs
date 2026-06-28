//! RGB-PQ BTQ chain backend, RPC client and indexer (Components 3, 4, 5).
//!
//! This crate is the substrate between RGB-PQ and a running `btqd` node:
//!   * [`backend::BtqChainBackend`] — the distinguished chain-backend trait;
//!   * [`rpc::BtqRpcClient`] — a real JSON-RPC client (typed errors, retry,
//!     network verification, never panics, never logs secrets);
//!   * [`indexer::Indexer`] / [`indexer::MemIndexer`] /
//!     [`indexer::sqlite::SqliteIndexer`] — watched-outpoint indexing with
//!     reorg rollback and rescan-from-height.
//!
//! See `ARCHITECTURE.md` §3.1 for how the backend maps onto RGB's
//! `ResolveWitness`.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod backend;
pub mod backend_impl;
pub mod indexer;
pub mod network;
pub mod rpc;

pub use backend::{
    node_unavailable, BtqChainBackend, BtqInclusionProof, BtqTx, BtqTxOut, ChainTip, TxStatus,
};
pub use indexer::{IndexedOutpoint, Indexer, MemIndexer};
pub use network::{BtqAuth, BtqRpcConfig};
pub use rpc::BtqRpcClient;
