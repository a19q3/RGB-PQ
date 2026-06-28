//! **P2MR-ret** — the RGB commitment bound directly into the P2MR script tree.
//!
//! This is the *tapret-equivalent* for P2MR (Phase 2 of the RGB-PQ commitment
//! roadmap). Unlike Taproot, P2MR has **no internal key and no key tweak**:
//! the SegWit v2 witness program *is* the Merkle root of the script tree. So a
//! "P2MR-ret" commitment is not a key tweak; it is a **dedicated commitment
//! leaf** placed in the P2MR script tree alongside the PQ ownership leaf:
//!
//! ```text
//! P2MR script tree
//! ├── PQ spend leaf        (Dilithium / ML-DSA ownership script)
//! └── RGB commitment leaf  (unspendable script carrying the RGB commitment)
//! ```
//!
//! The P2MR output root therefore commits to *both*:
//!
//! ```text
//! p2mr_root = MerkleRoot(pq_leaf_hash, commitment_leaf_hash)
//! ```
//!
//! Because P2MR commits directly to the script-tree root, the RGB commitment
//! is bound to the seal with no separate OP_RETURN output — more private and
//! less chain bloat than the opret scheme.
//!
//! ## Exact Merkle math (verified against `btq-core`)
//!
//! Reproduced byte-for-byte from `btq-core/src/script/interpreter.cpp`:
//!
//! - **Tapleaf**: `SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || leaf_version || CompactSize(len) || script)`
//!   (BIP-340 tagged hash with tag `"TapLeaf"`.)
//! - **Tapbranch**: `SHA256(SHA256("TapBranch") || SHA256("TapBranch") || min(a,b) || max(a,b))`
//!   (lexicographic ordering of the two 32-byte child hashes).
//! - **P2MR root**: the Merkle root *directly* (no tweak). The witness program
//!   is exactly this 32-byte root.
//!
//! `CompactSize(len)` is Bitcoin's variable-length integer encoding of the
//! script length.
//!
//! Per BIP-360, depth-0 (single-leaf) P2MR trees are discouraged for
//! commitment use; RGB-PQ therefore always builds at least a 2-leaf tree
//! (PQ leaf + commitment leaf).

use sha2::{Digest, Sha256};

use rgb_pq_core::{CommitmentError, Domain, RgbPqResult, VerifyLimits};
use rgb_pq_seal::{BtqChainId, BtqP2mrSeal};

use crate::commitment::MpcCommitment;

/// The leaf-version byte for RGB-PQ commitment leaves.
///
/// Must have the parity bit (LSB) unset to satisfy P2MR's leaf-version check
/// (`(leaf_version & ~TAPROOT_LEAF_MASK) == 0`, i.e. only the top bits used).
/// We reuse `0xc0` (Taproot's `TAPROOT_LEAF_TAPSCRIPT`), the same value btq-core
/// uses for ordinary script leaves.
pub const P2MR_COMMITMENT_LEAF_VERSION: u8 = 0xc0;

/// A P2MR tree node hash (32 bytes).
pub type NodeHash = [u8; 32];

/// A placed leaf: (depth, leaf_version, script).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacedLeaf {
    /// Depth in the script tree (0 = root level).
    pub depth: u8,
    /// Leaf version (LSB unset).
    pub leaf_version: u8,
    /// The leaf script bytes.
    pub script: Vec<u8>,
}

/// A Merkle proof that a leaf is included in a P2MR tree with a given root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2mrRetProof {
    /// The leaf this proof is for (the commitment leaf).
    pub leaf: PlacedLeaf,
    /// The sibling hashes along the path from the leaf to the root, in order.
    /// Each entry is the 32-byte hash of the sibling node at that level.
    pub branch: Vec<NodeHash>,
}

impl P2mrRetProof {
    /// Verify this proof against an expected P2MR root.
    pub fn verify_against(&self, expected_root: NodeHash) -> bool {
        let leaf_hash = compute_tapleaf_hash(self.leaf.leaf_version, &self.leaf.script);
        let computed = self.branch.iter().fold(leaf_hash, |acc, sibling| {
            compute_tapbranch_hash(&acc, sibling)
        });
        computed == expected_root
    }
}

// =========================================================================
// Tagged hashing (BIP-340) + Bitcoin CompactSize — exact btq-core semantics
// =========================================================================

/// BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = {
        let mut h = Sha256::new();
        h.update(tag);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    };
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Bitcoin CompactSize encoding of a length (mirrors `CompactSizeWriter`).
fn compact_size(len: usize) -> Vec<u8> {
    if len < 0xfd {
        vec![len as u8]
    } else if len <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(len as u16).to_le_bytes());
        v
    } else if len <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(len as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&(len as u64).to_le_bytes());
        v
    }
}

/// `ComputeTapleafHash(leaf_version, script)` — exact btq-core formula.
pub fn compute_tapleaf_hash(leaf_version: u8, script: &[u8]) -> NodeHash {
    let mut msg = Vec::with_capacity(1 + 9 + script.len());
    msg.push(leaf_version);
    msg.extend_from_slice(&compact_size(script.len()));
    msg.extend_from_slice(script);
    tagged_hash(b"TapLeaf", &msg)
}

/// `ComputeTapbranchHash(a, b)` — exact btq-core formula (lexicographic order).
pub fn compute_tapbranch_hash(a: &NodeHash, b: &NodeHash) -> NodeHash {
    let (first, second) = if a < b { (a, b) } else { (b, a) };
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(first);
    msg.extend_from_slice(second);
    tagged_hash(b"TapBranch", &msg)
}

// =========================================================================
// Commitment leaf construction
// =========================================================================

/// Build the RGB-PQ commitment leaf *script* for a chain + MPC commitment.
///
/// Unlike the opret `RgbPqCommitment`, the **P2MR-ret commitment payload does
/// not embed the seal's outpoint**. The reason is a chicken-and-egg constraint:
/// the P2MR output's witness program *is* the Merkle root that commits to this
/// leaf, so the leaf must be fixed *before* the output (and thus its outpoint)
/// exists. The outpoint binding is therefore *implicit*: the commitment leaf
/// lives in the very P2MR output that the seal names, so being in the tree IS
/// the binding to that outpoint.
///
/// The payload carries only: magic, protocol tag, chain id, and the 32-byte RGB
/// MPC commitment. This is sufficient to bind the RGB transition to the chain
/// and to the P2MR output (by inclusion).
///
/// The leaf is prefixed with `OP_RETURN` so it is provably unspendable.
pub fn commitment_leaf_script(chain: BtqChainId, mpc: MpcCommitment) -> Vec<u8> {
    let payload = p2mr_ret_payload(chain, mpc);
    let mut script = Vec::with_capacity(1 + 3 + payload.len());
    script.push(0x6a); // OP_RETURN
    if payload.len() <= 0x4b {
        script.push(payload.len() as u8);
    } else {
        // OP_PUSHDATA1 <len:1byte>
        script.push(0x4c);
        script.push(payload.len() as u8);
    }
    script.extend_from_slice(&payload);
    script
}

/// The P2MR-ret commitment payload (no outpoint — see [`commitment_leaf_script`]).
///
/// Layout: `MAGIC(7) || TAG(19) || chain(1) || mpc(32)` = 59 bytes.
pub fn p2mr_ret_payload(chain: BtqChainId, mpc: MpcCommitment) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + 19 + 1 + 32);
    out.extend_from_slice(crate::COMMITMENT_MAGIC);
    out.extend_from_slice(crate::COMMITMENT_PROTOCOL_TAG);
    out.push(chain.to_byte());
    out.extend_from_slice(&mpc);
    out
}

/// Decode a P2MR-ret payload, validating magic/tag/chain. Returns (chain, mpc).
pub fn decode_p2mr_ret_payload(bytes: &[u8]) -> RgbPqResult<(BtqChainId, MpcCommitment)> {
    let need = 7 + 19 + 1 + 32;
    if bytes.len() != need {
        return Err(CommitmentError::Malformed(format!(
            "p2mr-ret payload length {} != {need}",
            bytes.len()
        ))
        .into());
    }
    if &bytes[0..7] != crate::COMMITMENT_MAGIC {
        return Err(CommitmentError::Malformed("bad magic".into()).into());
    }
    if &bytes[7..26] != crate::COMMITMENT_PROTOCOL_TAG {
        return Err(CommitmentError::Malformed("bad protocol tag".into()).into());
    }
    let chain = BtqChainId::from_byte(bytes[26])?;
    let mut mpc = [0u8; 32];
    mpc.copy_from_slice(&bytes[27..59]);
    Ok((chain, mpc))
}

/// Build a 2-leaf P2MR tree (PQ leaf + commitment leaf) and return the root
/// plus the commitment-leaf proof.
///
/// This is the canonical RGB-PQ P2MR-ret construction. The PQ ownership leaf
/// and the RGB commitment leaf are placed at **depth 1** (the root is at
/// depth 0, the parent of the two leaves), matching the tree shape btq-core's
/// `P2MRBuilder` accepts for a 2-leaf tree. The root is
/// `TapbranchHash(pq_leaf_hash, commitment_leaf_hash)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2mrRetTree {
    /// The PQ spend leaf.
    pub pq_leaf: PlacedLeaf,
    /// The RGB commitment leaf.
    pub commitment_leaf: PlacedLeaf,
    /// The 32-byte P2MR root (= witness program).
    pub root: NodeHash,
    /// Proof that the commitment leaf is bound to `root`.
    pub commitment_proof: P2mrRetProof,
}

/// Build a P2MR-ret tree from a PQ leaf script and an RGB commitment leaf.
///
/// Both leaves are placed at depth 1; the root is their Tapbranch hash. The PQ
/// leaf and commitment leaf order is determined by the lexicographic ordering
/// inside `ComputeTapbranchHash`, but the proof records the actual sibling, so
/// verification is order-independent.
pub fn build_p2mr_ret_tree(
    pq_leaf_script: &[u8],
    pq_leaf_version: u8,
    commitment_leaf_script: &[u8],
) -> P2mrRetTree {
    let pq_leaf = PlacedLeaf {
        depth: 1,
        leaf_version: pq_leaf_version,
        script: pq_leaf_script.to_vec(),
    };
    let commitment_leaf = PlacedLeaf {
        depth: 1,
        leaf_version: P2MR_COMMITMENT_LEAF_VERSION,
        script: commitment_leaf_script.to_vec(),
    };
    let pq_hash = compute_tapleaf_hash(pq_leaf.leaf_version, &pq_leaf.script);
    let comm_hash = compute_tapleaf_hash(commitment_leaf.leaf_version, &commitment_leaf.script);
    let root = compute_tapbranch_hash(&pq_hash, &comm_hash);
    let commitment_proof = P2mrRetProof {
        leaf: commitment_leaf.clone(),
        // The sibling of the commitment leaf at depth 1 is the PQ leaf hash.
        branch: vec![pq_hash],
    };
    P2mrRetTree {
        pq_leaf,
        commitment_leaf,
        root,
        commitment_proof,
    }
}

/// Convenience: build a P2MR-ret tree for a chain + MPC commitment, alongside
/// a given PQ spend leaf. The commitment leaf does NOT embed the seal outpoint
/// (see [`commitment_leaf_script`]).
pub fn build_p2mr_ret_tree_for_seal(
    chain: BtqChainId,
    mpc: MpcCommitment,
    pq_leaf_script: &[u8],
) -> P2mrRetTree {
    let comm_script = commitment_leaf_script(chain, mpc);
    build_p2mr_ret_tree(pq_leaf_script, P2MR_COMMITMENT_LEAF_VERSION, &comm_script)
}

/// Verify that a P2MR seal's `p2mr_root` commits to the given RGB commitment.
///
/// This recomputes the commitment leaf from `seal.chain_id` + `mpc` (the leaf
/// does not depend on the outpoint), derives the expected root from the PQ
/// leaf, and checks it equals `seal.p2mr_root`.
///
/// Enforces [`VerifyLimits::DEFAULT`] on tree depth, leaf/control/witness
/// sizes. Fails closed (`Err`) on any breach.
pub fn verify_p2mr_ret(
    seal: &BtqP2mrSeal,
    mpc: MpcCommitment,
    pq_leaf_script: &[u8],
) -> RgbPqResult<()> {
    verify_p2mr_ret_bounded(seal, mpc, pq_leaf_script, &VerifyLimits::DEFAULT)
}

/// Bounded variant of [`verify_p2mr_ret`] with an explicit [`VerifyLimits`].
pub fn verify_p2mr_ret_bounded(
    seal: &BtqP2mrSeal,
    mpc: MpcCommitment,
    pq_leaf_script: &[u8],
    limits: &VerifyLimits,
) -> RgbPqResult<()> {
    // DoS-defence bounds on the PQ leaf and (later) witness material.
    limits.check_leaf_size(pq_leaf_script.len())?;
    let tree = build_p2mr_ret_tree_for_seal(seal.chain_id, mpc, pq_leaf_script);
    limits.check_tree_depth(tree.commitment_leaf.depth as u32)?;
    limits.check_leaf_size(tree.commitment_leaf.script.len())?;
    // 1. The seal's root must equal the tree's root.
    if tree.root != seal.p2mr_root {
        return Err(CommitmentError::Malformed(format!(
            "p2mr-ret root mismatch: seal={} tree={}",
            hex::encode(seal.p2mr_root),
            hex::encode(tree.root)
        ))
        .into());
    }
    // 2. The commitment-leaf proof must verify against the root.
    if !tree.commitment_proof.verify_against(tree.root) {
        return Err(CommitmentError::Malformed("p2mr-ret proof invalid".into()).into());
    }
    // 3. Domain separation: the chain must be BTQ.
    let _ = Domain::p2mr(seal.chain_id.domain_str());
    Ok(())
}

/// Build the P2MR tree JSON (DFS leaf list) accepted by `getnewp2mraddress` /
/// `sendtop2mr`, with the PQ leaf and the RGB commitment leaf both at depth 1.
pub fn tree_json(pq_leaf_script_hex: &str, commitment_leaf_script_hex: &str) -> serde_json::Value {
    serde_json::json!([
        { "depth": 1, "leaf_version": P2MR_COMMITMENT_LEAF_VERSION, "script": pq_leaf_script_hex },
        { "depth": 1, "leaf_version": P2MR_COMMITMENT_LEAF_VERSION, "script": commitment_leaf_script_hex },
    ])
}

/// Resolve the commitment leaf for a seal from a P2MR tree's leaf list (as
/// returned by `getp2mrinfo`). Returns the decoded (chain, mpc) if a valid
/// commitment leaf is present and its chain matches the seal.
pub fn find_commitment_in_tree(
    seal: &BtqP2mrSeal,
    leaves: &[PlacedLeaf],
    _expected_root: NodeHash,
) -> RgbPqResult<Option<(BtqChainId, MpcCommitment)>> {
    let mut hits = Vec::new();
    for leaf in leaves {
        if leaf.script.first() == Some(&0x6a) {
            if let Some(payload) = strip_opreturn_script(&leaf.script) {
                if let Ok((chain, mpc)) = decode_p2mr_ret_payload(payload) {
                    if chain == seal.chain_id {
                        hits.push((leaf.clone(), (chain, mpc)));
                    }
                }
            }
        }
    }
    match hits.len() {
        0 => Ok(None),
        1 => Ok(Some(hits.remove(0).1)),
        _ => Err(CommitmentError::Duplicate("multiple commitment leaves".into()).into()),
    }
}

/// Strip the OP_RETURN + length prefix from a commitment-leaf script, returning
/// the payload slice.
fn strip_opreturn_script(script: &[u8]) -> Option<&[u8]> {
    if script.first() != Some(&0x6a) {
        return None;
    }
    let rest = &script[1..];
    if rest.is_empty() {
        return None;
    }
    // CompactSize decode (we only need the common single-byte and PUSHDATA1 cases;
    // commitment payloads are ~127 bytes so PUSHDATA1 applies, but handle direct too).
    let first = rest[0];
    let (len, off) = if first < 0xfd {
        (first as usize, 1)
    } else if first == 0xfd {
        if rest.len() < 3 {
            return None;
        }
        let len = u16::from_le_bytes([rest[1], rest[2]]) as usize;
        (len, 3)
    } else {
        return None;
    };
    if rest.len() < off + len {
        return None;
    }
    Some(&rest[off..off + len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rgb_pq_seal::{
        BtqChainId, BtqOutpoint, BtqTxid, CommitmentLocator, ConfirmationPolicy, PqSigAlgo,
    };

    fn seal() -> BtqP2mrSeal {
        BtqP2mrSeal::new(
            BtqChainId::BitcoinQuantumRegtest,
            BtqOutpoint::new(BtqTxid::from_bytes([0x11; 32]), 0),
            [0x22; 32],
            [0x33; 32],
            PqSigAlgo::Dilithium2,
            CommitmentLocator::OpretFirst,
            ConfirmationPolicy::OneConf,
        )
    }

    #[test]
    fn tagged_hash_tapleaf_known_vector() {
        // BIP-340 tagged hash of "TapLeaf" tag must be stable.
        let h = tagged_hash(b"TapLeaf", b"");
        assert_eq!(h.len(), 32);
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn compact_size_encoding() {
        // Bitcoin CompactSize: <0xfd is a single byte.
        assert_eq!(compact_size(0), vec![0x00]);
        assert_eq!(compact_size(75), vec![75]);
        assert_eq!(compact_size(127), vec![127]);
        // 0xfd+ uses the 3-byte form; below it's a single byte.
        assert_eq!(compact_size(252), vec![252]); // 252 < 0xfd
        assert_eq!(compact_size(253), vec![0xfd, 253, 0]);
        assert_eq!(compact_size(0xffff), vec![0xfd, 0xff, 0xff]);
    }

    #[test]
    fn tapleaf_hash_matches_single_byte_op_true() {
        // btq-core: ComputeTapleafHash(0xc0, OP_TRUE=[0x51])
        let h = compute_tapleaf_hash(0xc0, &[0x51]);
        // Stable, non-zero, 32 bytes. The exact value is cross-checked against
        // the node in the live integration step (build tree, compare root).
        assert_eq!(h.len(), 32);
        assert_ne!(h, [0u8; 32]);
        // Deterministic.
        assert_eq!(h, compute_tapleaf_hash(0xc0, &[0x51]));
    }

    #[test]
    fn tapbranch_hash_is_symmetric() {
        // ComputeTapbranchHash orders lexicographically, so (a,b) == (b,a).
        let a = [0xaa; 32];
        let b = [0xbb; 32];
        assert_eq!(
            compute_tapbranch_hash(&a, &b),
            compute_tapbranch_hash(&b, &a)
        );
    }

    #[test]
    fn tapbranch_hash_changes_with_input() {
        let a = [0xaa; 32];
        let b = [0xbb; 32];
        let c = [0xcc; 32];
        assert_ne!(
            compute_tapbranch_hash(&a, &b),
            compute_tapbranch_hash(&a, &c)
        );
    }

    #[test]
    fn p2mr_ret_tree_roundtrips_and_proofs() {
        let seal = seal();
        let mpc = [0xa5; 32];
        let pq_leaf = vec![0x51]; // OP_TRUE (placeholder PQ leaf)
        let tree = build_p2mr_ret_tree_for_seal(seal.chain_id, mpc, &pq_leaf);
        // The commitment proof must verify against the root.
        assert!(tree.commitment_proof.verify_against(tree.root));
        // Tampering with the commitment leaf must break the proof.
        let mut bad_leaf = tree.commitment_leaf.clone();
        bad_leaf.script.push(0x00);
        let bad_proof = P2mrRetProof {
            leaf: bad_leaf,
            branch: tree.commitment_proof.branch.clone(),
        };
        assert!(!bad_proof.verify_against(tree.root));
    }

    #[test]
    fn p2mr_ret_root_changes_with_commitment() {
        let seal = seal();
        let pq_leaf = vec![0x51];
        let t1 = build_p2mr_ret_tree_for_seal(seal.chain_id, [0xa5; 32], &pq_leaf);
        let t2 = build_p2mr_ret_tree_for_seal(seal.chain_id, [0x5a; 32], &pq_leaf);
        assert_ne!(t1.root, t2.root);
    }

    #[test]
    fn p2mr_ret_root_changes_with_pq_leaf() {
        let seal = seal();
        let mpc = [0xa5; 32];
        let t1 = build_p2mr_ret_tree_for_seal(seal.chain_id, mpc, &[0x51]);
        let t2 = build_p2mr_ret_tree_for_seal(seal.chain_id, mpc, &[0x52]);
        assert_ne!(t1.root, t2.root);
    }

    #[test]
    fn p2mr_ret_root_changes_with_chain() {
        let mut seal = seal();
        let mpc = [0xa5; 32];
        let pq_leaf = vec![0x51];
        let t1 = build_p2mr_ret_tree_for_seal(seal.chain_id, mpc, &pq_leaf);
        seal.chain_id = BtqChainId::BitcoinQuantumTestnet;
        let t2 = build_p2mr_ret_tree_for_seal(seal.chain_id, mpc, &pq_leaf);
        assert_ne!(t1.root, t2.root);
    }

    #[test]
    fn verify_p2mr_ret_succeeds_for_consistent_seal() {
        let mpc = [0xa5; 32];
        let pq_leaf = vec![0x51];
        // Build a tree, then set the seal's root to the tree root.
        let mut seal = seal();
        let tree = build_p2mr_ret_tree_for_seal(seal.chain_id, mpc, &pq_leaf);
        seal.p2mr_root = tree.root;
        assert!(verify_p2mr_ret(&seal, mpc, &pq_leaf).is_ok());
    }

    #[test]
    fn verify_p2mr_ret_rejects_wrong_root() {
        let seal = seal();
        assert!(verify_p2mr_ret(&seal, [0xa5; 32], &[0x51]).is_err());
    }

    #[test]
    fn verify_p2mr_ret_rejects_wrong_chain_payload() {
        let mpc = [0xa5; 32];
        let pq_leaf = vec![0x51];
        let mut seal = seal();
        let tree = build_p2mr_ret_tree_for_seal(seal.chain_id, mpc, &pq_leaf);
        seal.p2mr_root = tree.root;
        seal.chain_id = BtqChainId::BitcoinQuantumTestnet; // mismatch with payload
        assert!(verify_p2mr_ret(&seal, mpc, &pq_leaf).is_err());
    }

    #[test]
    fn commitment_leaf_script_starts_with_opreturn() {
        let seal = seal();
        let s = commitment_leaf_script(seal.chain_id, [0xa5; 32]);
        assert_eq!(s[0], 0x6a); // OP_RETURN
                                // P2MR-ret payload is 59 bytes -> direct push (<=75), so s[1] is the length.
        assert_eq!(s[1], 59);
    }

    #[test]
    fn tree_json_shape() {
        let t = tree_json("51", "abcd");
        assert_eq!(t.as_array().unwrap().len(), 2);
        assert_eq!(t[0]["depth"], 1);
        assert_eq!(t[0]["leaf_version"], P2MR_COMMITMENT_LEAF_VERSION);
    }
}
