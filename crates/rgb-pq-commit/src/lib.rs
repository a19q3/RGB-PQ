//! RGB transition commitment binder (Component 7).
//!
//! Binds an RGB state transition (its bundle commitment) into a BTQ closing
//! transaction via an explicit **OP_RETURN output** (the RGB "opret" anchor),
//! and verifies that binding.
//!
//! Design (see `ARCHITECTURE.md` §3.3 and §5): the RGB validator requires the
//! closing transaction to carry an OP_RETURN (or P2TR) output whose payload is
//! the LNPBP-4 multi-protocol commitment. P2MR itself is neither, so the
//! commitment lives in a separate OP_RETURN output in the same tx that spends
//! the P2MR seal. This is the simplest explicit, locally-testable commitment
//! and is the one the brief prefers; we do **not** implement tapret hiding.
//!
//! This crate is intentionally split into two layers:
//!   * [`commitment`] — the deterministic, domain-separated
//!     [`RgbPqCommitment`] payload and its verification against a seal;
//!   * [`anchor`] — a thin bridge to RGB's real `mpc::Commitment` /
//!     `OpretProof` / `Anchor` types, used by the RGB integration crate to
//!     embed the commitment into a `bitcoin::Transaction` via RGB's own
//!     `EmbedCommitVerify` impl.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod anchor;
pub mod commitment;

pub use anchor::{embed_opret_commitment, verify_opret_anchor, OpretAnchorError};
pub use commitment::{
    CommitmentPayload, RgbPqCommitment, COMMITMENT_MAGIC, COMMITMENT_PROTOCOL_TAG,
};
