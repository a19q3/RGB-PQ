//! RGB transition commitment binder (Component 7).
//!
//! Binds an RGB state transition (its bundle commitment) into a BTQ closing
//! transaction via one of two commitment schemes:
//!   * **Opret** (Phase 1) — an explicit OP_RETURN output;
//!   * **P2MR-ret** (Phase 2) — a dedicated leaf in the P2MR script tree;
//!   * **Multi-protocol P2MR** (Phase 3) — multiple RGB contracts share one P2MR tree.
//!
//! See `ARCHITECTURE.md` and `docs/commitment-binding.md`.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod anchor;
pub mod commitment;
pub mod multi;
pub mod p2mrret;

pub use anchor::{embed_opret_commitment, verify_opret_anchor, OpretAnchorError};
pub use commitment::{
    strip_op_return, CommitmentPayload, MpcCommitment, RgbPqCommitment, COMMITMENT_MAGIC,
    COMMITMENT_PROTOCOL_TAG,
};
pub use multi::{
    build_multi_protocol_tree, multi_protocol_commitment_leaf, verify_multi_protocol_commitment,
    MultiProtocolP2mrTree,
};
pub use p2mrret::{
    build_p2mr_ret_tree, build_p2mr_ret_tree_for_seal, commitment_leaf_script,
    compute_tapbranch_hash, compute_tapleaf_hash, find_commitment_in_tree, tree_json,
    verify_p2mr_ret, NodeHash, P2mrRetProof, P2mrRetTree, PlacedLeaf, P2MR_COMMITMENT_LEAF_VERSION,
};
