//! RGB-PQ core: typed errors + domain separation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
//! This crate defines the cross-cutting, security-sensitive primitives shared
//! by every RGB-PQ component:
//!   * a typed error hierarchy (no stringly-typed security errors);
//!   * the canonical domain-separation prefix used by every seal encoding and
//!     commitment digest.
//!
//! Nothing here touches a network or a secret.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod domain;
pub mod error;

pub use domain::{Domain, DOMAIN_SEPARATION_VERSION, DOMAIN_TAG};
pub use error::{
    BtqFeature, ChainConfusion, CommitmentError, IndexError, InvalidSealCloseReason,
    MalformedSealError, NodeUnavailable, OwnerAlgoError, ResolveError, RgbPqError, RpcError,
    SealError, SealStateError, UnknownSealStateReason, UnsupportedFeature,
};

/// Convenience alias for the crate's fallible return type.
pub type RgbPqResult<T> = core::result::Result<T, RgbPqError>;
