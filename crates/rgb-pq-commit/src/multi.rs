//! Phase 3 — multi-protocol P2MR commitment tree.
//!
//! Allows multiple RGB contracts to share one P2MR commitment structure: each
//! contract's MPC commitment gets its own leaf in the P2MR script tree, and
//! the P2MR root commits to all of them alongside the PQ ownership leaf.
//!
//! ```text
//! P2MR script tree
//! ├── PQ spend leaf
//! ├── RGB commitment leaf (contract A)
//! ├── RGB commitment leaf (contract B)
//! └── ...
//! ```
//!
//! This is analogous to RGB's multi-protocol commitment (MPC) tree, but at the
//! P2MR script-tree level. Each commitment leaf is domain-separated by its
//! position + the contract's protocol id.

use rgb_pq_core::{CommitmentError, RgbPqResult};
use rgb_pq_seal::BtqChainId;

use crate::commitment::MpcCommitment;
use crate::p2mrret::{
    compute_tapbranch_hash, compute_tapleaf_hash, NodeHash, PlacedLeaf,
    P2MR_COMMITMENT_LEAF_VERSION,
};

/// A multi-protocol P2MR commitment tree: one PQ leaf + N commitment leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiProtocolP2mrTree {
    /// The PQ spend leaf.
    pub pq_leaf: PlacedLeaf,
    /// The commitment leaves (one per contract/protocol).
    pub commitment_leaves: Vec<PlacedLeaf>,
    /// The 32-byte P2MR root.
    pub root: NodeHash,
}

/// Build a multi-protocol P2MR tree from a PQ leaf + multiple commitment leaves.
///
/// The leaves are arranged as: PQ leaf at depth 1, each commitment leaf also
/// at depth 1 (siblings of PQ leaf in a balanced tree). For >2 leaves the tree
/// is built by successively combining pairs.
pub fn build_multi_protocol_tree(
    pq_leaf_script: &[u8],
    commitment_leaf_scripts: &[Vec<u8>],
) -> RgbPqResult<MultiProtocolP2mrTree> {
    if commitment_leaf_scripts.is_empty() {
        return Err(CommitmentError::Malformed(
            "multi-protocol tree needs at least one commitment leaf".into(),
        )
        .into());
    }

    let pq_leaf = PlacedLeaf {
        depth: 1,
        leaf_version: P2MR_COMMITMENT_LEAF_VERSION,
        script: pq_leaf_script.to_vec(),
    };

    let mut leaves: Vec<PlacedLeaf> = commitment_leaf_scripts
        .iter()
        .map(|s| PlacedLeaf {
            depth: 1,
            leaf_version: P2MR_COMMITMENT_LEAF_VERSION,
            script: s.clone(),
        })
        .collect();

    // Compute all leaf hashes.
    let pq_hash = compute_tapleaf_hash(pq_leaf.leaf_version, &pq_leaf.script);
    let hashes: Vec<NodeHash> = leaves
        .iter()
        .map(|l| compute_tapleaf_hash(l.leaf_version, &l.script))
        .collect();

    // Build the tree: combine PQ hash + first commitment hash, then fold in
    // remaining commitment hashes. For a 3-leaf tree (PQ + 2 commitments):
    //   root = Branch(Branch(pq, c0), c1)
    let mut root = compute_tapbranch_hash(&pq_hash, &hashes[0]);
    for h in hashes.iter().skip(1) {
        root = compute_tapbranch_hash(&root, h);
    }

    // Update leaf depths for the combined tree.
    for (i, leaf) in leaves.iter_mut().enumerate() {
        leaf.depth = (1 + i) as u8;
    }

    Ok(MultiProtocolP2mrTree {
        pq_leaf,
        commitment_leaves: leaves,
        root,
    })
}

/// Build a multi-protocol commitment leaf for a given chain + MPC + protocol
/// index (to domain-separate multiple contracts sharing one P2MR output).
pub fn multi_protocol_commitment_leaf(
    chain: BtqChainId,
    mpc: MpcCommitment,
    protocol_index: u8,
) -> Vec<u8> {
    let payload = crate::p2mrret::p2mr_ret_payload(chain, mpc);
    let mut script = Vec::with_capacity(1 + 1 + 1 + payload.len());
    script.push(0x6a); // OP_RETURN
                       // Prefix with protocol index for domain separation between contracts.
    script.push(0x01); // push 1 byte
    script.push(protocol_index);
    if payload.len() <= 0x4b {
        script.push(payload.len() as u8);
    } else {
        script.push(0x4c);
        script.push(payload.len() as u8);
    }
    script.extend_from_slice(&payload);
    script
}

/// Verify that a specific commitment leaf (identified by protocol_index) is
/// bound to the P2MR root, given all leaves.
pub fn verify_multi_protocol_commitment(
    root: NodeHash,
    pq_leaf_script: &[u8],
    commitment_leaf_scripts: &[Vec<u8>],
) -> RgbPqResult<()> {
    let tree = build_multi_protocol_tree(pq_leaf_script, commitment_leaf_scripts)?;
    if tree.root != root {
        return Err(CommitmentError::Malformed(format!(
            "multi-protocol root mismatch: expected={} got={}",
            hex::encode(root),
            hex::encode(tree.root)
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2mrret::build_p2mr_ret_tree;

    #[test]
    fn multi_protocol_tree_single_commitment() {
        // With one commitment leaf, this is equivalent to a standard P2MR-ret tree.
        let pq = vec![0x51u8];
        let comm = vec![0x6au8, 0x01, 0x00]; // minimal OP_RETURN leaf
        let tree = build_multi_protocol_tree(&pq, std::slice::from_ref(&comm)).unwrap();
        // Compare with the standard 2-leaf P2MR-ret tree.
        let standard = build_p2mr_ret_tree(&pq, P2MR_COMMITMENT_LEAF_VERSION, &comm);
        assert_eq!(tree.root, standard.root);
    }

    #[test]
    fn multi_protocol_tree_two_commitments() {
        let pq = vec![0x51u8];
        let c0 = multi_protocol_commitment_leaf(BtqChainId::BitcoinQuantumRegtest, [0xa5; 32], 0);
        let c1 = multi_protocol_commitment_leaf(BtqChainId::BitcoinQuantumRegtest, [0xb6; 32], 1);
        let tree = build_multi_protocol_tree(&pq, &[c0, c1]).unwrap();
        // Root must be non-zero and deterministic.
        assert_ne!(tree.root, [0u8; 32]);
        // Verify round-trip.
        verify_multi_protocol_commitment(
            tree.root,
            &pq,
            &tree
                .commitment_leaves
                .iter()
                .map(|l| l.script.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    }

    #[test]
    fn multi_protocol_tree_empty_rejected() {
        assert!(build_multi_protocol_tree(&[0x51], &[]).is_err());
    }

    #[test]
    fn multi_protocol_root_changes_with_extra_commitment() {
        let pq = vec![0x51u8];
        let c0 = multi_protocol_commitment_leaf(BtqChainId::BitcoinQuantumRegtest, [0xa5; 32], 0);
        let t1 = build_multi_protocol_tree(&pq, std::slice::from_ref(&c0)).unwrap();
        let c1 = multi_protocol_commitment_leaf(BtqChainId::BitcoinQuantumRegtest, [0xb6; 32], 1);
        let t2 = build_multi_protocol_tree(&pq, &[c0, c1]).unwrap();
        assert_ne!(t1.root, t2.root);
    }

    #[test]
    fn protocol_index_domain_separates() {
        let c0 = multi_protocol_commitment_leaf(BtqChainId::BitcoinQuantumRegtest, [0xa5; 32], 0);
        let c1 = multi_protocol_commitment_leaf(BtqChainId::BitcoinQuantumRegtest, [0xa5; 32], 1);
        // Same MPC, different protocol index → different leaf scripts.
        assert_ne!(c0, c1);
    }
}
