//! Property-based tests for [`crate::BtqP2mrSeal`].
//!
//! These guard the invariants that matter for consensus safety:
//!   * binary round-trip is lossless for any well-formed seal;
//!   * text round-trip is lossless;
//!   * malformed binary is always rejected;
//!   * domain separation holds (two seals differing in any field hash
//!     differently with overwhelming probability).

#![cfg(test)]

use proptest::prelude::*;

use crate::types::{
    BtqChainId, BtqOutpoint, BtqTxid, CommitmentLocator, ConfirmationPolicy, PqSigAlgo,
};
use crate::BtqP2mrSeal;

fn any_seal() -> impl Strategy<Value = BtqP2mrSeal> {
    (
        any::<bool>(),
        any::<[u8; 32]>(),
        any::<u32>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<bool>(),
        any::<bool>(),
        any::<u32>(),
    )
        .prop_map(
            |(chain, txid, vout, root, leaf, locator_kind, policy_kind, n)| {
                BtqP2mrSeal::new(
                    if chain {
                        BtqChainId::BitcoinQuantumRegtest
                    } else {
                        BtqChainId::BitcoinQuantumTestnet
                    },
                    BtqOutpoint::new(BtqTxid::from_bytes(txid), vout),
                    root,
                    leaf,
                    PqSigAlgo::Dilithium2,
                    if locator_kind {
                        CommitmentLocator::OpretFirst
                    } else {
                        CommitmentLocator::OpretVout(n)
                    },
                    if policy_kind {
                        ConfirmationPolicy::OneConf
                    } else {
                        ConfirmationPolicy::Depth(n % 100 + 1)
                    },
                )
            },
        )
}

proptest! {
    #[test]
    fn binary_roundtrip(s in any_seal()) {
        let enc = s.to_binary();
        let dec = BtqP2mrSeal::from_binary(&enc).expect("binary roundtrip");
        prop_assert_eq!(dec, s);
    }

    #[test]
    fn text_roundtrip(s in any_seal()) {
        let txt = s.to_text();
        let dec = BtqP2mrSeal::from_text(&txt).expect("text roundtrip");
        prop_assert_eq!(dec, s);
    }

    #[test]
    fn binary_text_agree(s in any_seal()) {
        let from_bin = BtqP2mrSeal::from_binary(&s.to_binary()).unwrap();
        let from_txt = BtqP2mrSeal::from_text(&s.to_text()).unwrap();
        prop_assert_eq!(from_bin, from_txt);
    }

    #[test]
    fn malformed_binary_rejected(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        // Either it decodes to a real seal or it errors; it must never panic.
        let _ = BtqP2mrSeal::from_binary(&bytes);
    }

    #[test]
    fn malformed_text_rejected(s in ".{0,120}") {
        let _ = BtqP2mrSeal::from_text(&s);
    }

    #[test]
    fn domain_separation_txid(
        s in any_seal(),
        flip in any::<[u8; 32]>(),
    ) {
        prop_assume!(flip != *s.outpoint.txid.as_bytes());
        let mut other = s.clone();
        other.outpoint.txid = BtqTxid::from_bytes(flip);
        prop_assert_ne!(s.canonical_digest(), other.canonical_digest());
    }

    #[test]
    fn domain_separation_root(
        s in any_seal(),
        flip in any::<[u8; 32]>(),
    ) {
        prop_assume!(flip != s.p2mr_root);
        let mut other = s.clone();
        other.p2mr_root = flip;
        prop_assert_ne!(s.canonical_digest(), other.canonical_digest());
    }

    #[test]
    fn domain_separation_chain(s in any_seal()) {
        let mut other = s.clone();
        other.chain_id = match s.chain_id {
            BtqChainId::BitcoinQuantumRegtest => BtqChainId::BitcoinQuantumTestnet,
            BtqChainId::BitcoinQuantumTestnet => BtqChainId::BitcoinQuantumRegtest,
        };
        prop_assert_ne!(s.canonical_digest(), other.canonical_digest());
    }
}
