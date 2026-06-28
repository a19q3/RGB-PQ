//! RGB-PQ P2MR seal resolver and `ResolveWitness` bridge (Components 6).
//!
//! Two responsibilities:
//!   * [`resolver::SealResolver`] — resolves a [`BtqP2mrSeal`] to a
//!     [`resolver::SealState`], verifying the full P2MR / Dilithium /
//!     commitment / finality chain.
//!   * [`witness::BtqWitnessResolver`] — implements RGB's
//!     [`rgbcore::validation::ResolveWitness`] over a BTQ backend, so the RGB
//!     validator can confirm witness transactions on BTQ.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod resolver;
pub mod witness;

pub use resolver::{SealResolver, SealState};
pub use witness::{BtqWitnessResolver, ChainNetMapping};
