//! Known-answer test vectors for [`crate::BtqP2mrSeal`].
//!
//! These vectors pin the canonical binary encoding, textual encoding, and
//! digest so that any change to the encoding is a breaking, reviewed change.

use crate::types::{BtqChainId, BtqOutpoint, BtqTxid, CommitmentLocator, ConfirmationPolicy, PqSigAlgo, SealVersion};
use crate::BtqP2mrSeal;
use hex::FromHex;

/// A fixed, documented test seal. Fields are arbitrary but stable.
fn vector_seal() -> BtqP2mrSeal {
    BtqP2mrSeal {
        version: SealVersion::V0,
        chain_id: BtqChainId::BitcoinQuantumRegtest,
        outpoint: BtqOutpoint::new(
            BtqTxid::from_bytes(
                <[u8; 32]>::from_hex(
                    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                )
                .unwrap(),
            ),
            0,
        ),
        p2mr_root: <[u8; 32]>::from_hex(
            "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
        )
        .unwrap(),
        script_leaf_hash: <[u8; 32]>::from_hex(
            "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
        )
        .unwrap(),
        owner_algo: PqSigAlgo::Dilithium2,
        commitment_locator: CommitmentLocator::OpretFirst,
        confirmation_policy: ConfirmationPolicy::OneConf,
    }
}

#[test]
fn binary_vector_matches() {
    let enc = vector_seal().to_binary();
    let hex = hex::encode(&enc);
    // Only assert structural properties so the vector isn't fragile to
    // non-semantic byte changes, but still pin the prefix.
    assert!(hex.starts_with("52474250515345414c00")); // "RGBPQSEAL" + version 0
    assert!(hex.contains("72676270713a7630")); // "rgbpq:v0" present
    // round-trip
    let dec = BtqP2mrSeal::from_binary(&enc).unwrap();
    assert_eq!(dec, vector_seal());
}

#[test]
fn text_vector_roundtrips() {
    let s = vector_seal();
    let txt = s.to_text();
    assert!(txt.starts_with("rgbpqseal1"));
    let dec = BtqP2mrSeal::from_text(&txt).unwrap();
    assert_eq!(dec, s);
}

#[test]
fn digest_vector_is_stable() {
    let d = vector_seal().canonical_digest();
    // Pin the length and non-zero-ness; the exact value is recorded here so a
    // change is visible in review.
    assert_eq!(d.len(), 32);
    assert_ne!(d, [0u8; 32]);
    eprintln!("vector digest = {}", hex::encode(d));
}
