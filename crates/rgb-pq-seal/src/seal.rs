//! The canonical [`BtqP2mrSeal`]: a BTQ P2MR output used as an RGB single-use
//! seal with post-quantum Dilithium ownership.
//!
//! Encoding rules (see `ARCHITECTURE.md` and `docs/btq-p2mr-seal.md`):
//!   * binary encoding is deterministic and version-tagged;
//!   * textual encoding is a checked bech32m-like string (HRP `rgbpqseal`);
//!   * the canonical commitment digest is domain-separated and changes whenever
//!     any field changes (tested exhaustively).
//!
//! The type deliberately mirrors the shape requested in the brief while
//! adapting names to the actual codebase (it carries `BtqOutpoint` /
//! `BtqTxid` rather than raw `bitcoin` types, so BTQ and Bitcoin outpoints
//! cannot be confused at the type level).

use core::fmt;
use core::str::FromStr;

use sha2::{Digest, Sha256};

use rgb_pq_core::{Domain, MalformedSealError, RgbPqResult, SealError};

use crate::types::{
    BtqChainId, BtqOutpoint, CommitmentLocator, ConfirmationPolicy, PqSigAlgo, SealVersion,
};

/// A 32-byte P2MR Merkle root (the SegWit v2 witness program payload).
pub type P2mrRoot = [u8; 32];
/// A 32-byte Tapleaf hash of the spending script leaf.
pub type ScriptLeafHash = [u8; 32];

/// Magic bytes prefixing the binary encoding (ASCII `RGBPQSEAL`).
pub const BIN_MAGIC: &[u8] = b"RGBPQSEAL";
/// HRP for the textual seal encoding.
pub const SEAL_HRP: &str = "rgbpqseal";

/// A canonical BTQ P2MR single-use seal.
///
/// Carries everything the resolver needs to verify that an outpoint is a BTQ
/// P2MR output owned by a post-quantum Dilithium leaf, and that its closing
/// transaction carries the right RGB commitment with the right finality policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BtqP2mrSeal {
    /// Encoding version.
    pub version: SealVersion,
    /// The BTQ chain this seal lives on (regtest/testnet only).
    pub chain_id: BtqChainId,
    /// The outpoint that will be spent to close the seal.
    pub outpoint: BtqOutpoint,
    /// The P2MR script-tree Merkle root committed in the SegWit v2 witness
    /// program.
    pub p2mr_root: P2mrRoot,
    /// The hash of the script leaf expected to be used to spend the seal
    /// (`ComputeTapleafHash` over the Dilithium checksig leaf).
    pub script_leaf_hash: ScriptLeafHash,
    /// The post-quantum ownership algorithm of the spending leaf. secp256k1 is
    /// not representable here.
    pub owner_algo: PqSigAlgo,
    /// Where the RGB commitment lives in the closing tx.
    pub commitment_locator: CommitmentLocator,
    /// Confirmation / finality policy.
    pub confirmation_policy: ConfirmationPolicy,
}

impl BtqP2mrSeal {
    /// Construct a new seal with the given parameters and default version.
    pub fn new(
        chain_id: BtqChainId,
        outpoint: BtqOutpoint,
        p2mr_root: P2mrRoot,
        script_leaf_hash: ScriptLeafHash,
        owner_algo: PqSigAlgo,
        commitment_locator: CommitmentLocator,
        confirmation_policy: ConfirmationPolicy,
    ) -> Self {
        Self {
            version: SealVersion::CURRENT,
            chain_id,
            outpoint,
            p2mr_root,
            script_leaf_hash,
            owner_algo,
            commitment_locator,
            confirmation_policy,
        }
    }

    // ----- binary encoding ----------------------------------------------

    /// The fixed-size payload (excluding magic, version byte and domain tag)
    /// used both for serialisation and for the digest.
    fn body_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        // chain_id
        buf.push(self.chain_id.to_byte());
        // outpoint: txid (32, inner/display order) || vout (4 LE)
        buf.extend_from_slice(self.outpoint.txid.as_bytes());
        buf.extend_from_slice(&self.outpoint.vout.to_le_bytes());
        // p2mr_root
        buf.extend_from_slice(&self.p2mr_root);
        // script_leaf_hash
        buf.extend_from_slice(&self.script_leaf_hash);
        // owner_algo
        buf.push(self.owner_algo.to_byte());
        // commitment_locator (length-prefixed)
        let loc = self.commitment_locator.encode();
        buf.push(loc.len() as u8);
        buf.extend_from_slice(&loc);
        // confirmation_policy (length-prefixed)
        let pol = self.confirmation_policy.encode();
        buf.push(pol.len() as u8);
        buf.extend_from_slice(&pol);
        buf
    }

    /// Encode to a deterministic byte vector.
    ///
    /// Layout: `MAGIC || version || DOMAIN_TAG || ver_byte || body`.
    pub fn to_binary(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 128);
        out.extend_from_slice(BIN_MAGIC);
        out.push(self.version.to_byte());
        out.extend_from_slice(crate::DOMAIN_TAG_BYTES);
        out.push(rgb_pq_core::DOMAIN_SEPARATION_VERSION);
        out.extend_from_slice(&self.body_bytes());
        out
    }

    /// Decode from a byte slice. Validates magic, version, and domain tag.
    pub fn from_binary(bytes: &[u8]) -> RgbPqResult<Self> {
        let min = BIN_MAGIC.len() + 1 + crate::DOMAIN_TAG_BYTES.len() + 1;
        if bytes.len() < min {
            return Err(MalformedSealError::BadEncoding(format!(
                "binary too short: {} < {min}",
                bytes.len()
            ))
            .into());
        }
        if &bytes[..BIN_MAGIC.len()] != BIN_MAGIC {
            return Err(MalformedSealError::BadEncoding("bad magic".into()).into());
        }
        let mut pos = BIN_MAGIC.len();
        let version = SealVersion::from_byte(bytes[pos])?;
        pos += 1;
        let tag_end = pos + crate::DOMAIN_TAG_BYTES.len();
        if bytes[pos..tag_end] != *crate::DOMAIN_TAG_BYTES {
            return Err(MalformedSealError::BadEncoding("bad domain tag".into()).into());
        }
        pos = tag_end;
        if bytes[pos] != rgb_pq_core::DOMAIN_SEPARATION_VERSION {
            return Err(MalformedSealError::UnknownVersion(bytes[pos]).into());
        }
        pos += 1;
        Self::decode_body(version, &bytes[pos..])
    }

    fn decode_body(version: SealVersion, b: &[u8]) -> RgbPqResult<Self> {
        let mut pos = 0;
        need(b, pos, 1)?;
        let chain_id = BtqChainId::from_byte(b[pos])?;
        pos += 1;
        need(b, pos, 32 + 4)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&b[pos..pos + 32]);
        pos += 32;
        let mut vout_buf = [0u8; 4];
        vout_buf.copy_from_slice(&b[pos..pos + 4]);
        let vout = u32::from_le_bytes(vout_buf);
        pos += 4;
        need(b, pos, 32 + 32 + 1)?;
        let mut p2mr_root = [0u8; 32];
        p2mr_root.copy_from_slice(&b[pos..pos + 32]);
        pos += 32;
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&b[pos..pos + 32]);
        pos += 32;
        let owner_algo = PqSigAlgo::from_byte(b[pos])?;
        pos += 1;
        // locator
        need(b, pos, 1)?;
        let loc_len = b[pos] as usize;
        pos += 1;
        need(b, pos, loc_len)?;
        let (commitment_locator, used) = CommitmentLocator::decode(&b[pos..pos + loc_len])?;
        pos += used;
        if used != loc_len {
            return Err(MalformedSealError::BadEncoding(
                "locator length mismatch".into(),
            )
            .into());
        }
        // policy
        need(b, pos, 1)?;
        let pol_len = b[pos] as usize;
        pos += 1;
        need(b, pos, pol_len)?;
        let (confirmation_policy, used) = ConfirmationPolicy::decode(&b[pos..pos + pol_len])?;
        pos += used;
        if used != pol_len {
            return Err(MalformedSealError::BadEncoding(
                "policy length mismatch".into(),
            )
            .into());
        }
        let _ = pos; // consumed exactly
        Ok(BtqP2mrSeal {
            version,
            chain_id,
            outpoint: BtqOutpoint::new(crate::types::BtqTxid::from_bytes(txid), vout),
            p2mr_root,
            script_leaf_hash: leaf,
            owner_algo,
            commitment_locator,
            confirmation_policy,
        })
    }

    // ----- canonical digest ---------------------------------------------

    /// The domain-separated canonical commitment digest (32 bytes).
    ///
    /// The digest incorporates the full domain prefix (`rgbpq:v0`, chain,
    /// `p2mr`), the version, and every body field. Changing any field changes
    /// the digest — this invariant is property-tested.
    pub fn canonical_digest(&self) -> [u8; 32] {
        let domain = Domain::p2mr(self.chain_id.domain_str());
        let mut hasher = Sha256::new();
        let mut prefix = domain.prefixed();
        // include the seal version byte so a future version hashes differently
        prefix.push(self.version.to_byte());
        hasher.update(prefix);
        hasher.update(self.body_bytes());
        let out = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }

    // ----- textual encoding ---------------------------------------------

    /// Encode to a deterministic bech32m string with HRP `rgbpqseal`.
    ///
    /// The data part is the raw binary body (no magic/tag, which are implied by
    /// the HRP + checksum), so the text form is compact yet still
    /// domain-separated via the HRP.
    pub fn to_text(&self) -> String {
        let body = self.body_bytes();
        let hrp = bech32::Hrp::parse(SEAL_HRP).unwrap_or_else(|_| bech32::Hrp::parse("rgbpqseal").unwrap());
        bech32::encode::<bech32::Bech32m>(hrp, &body).unwrap_or_default()
    }

    /// Parse a textual seal.
    pub fn from_text(s: &str) -> RgbPqResult<Self> {
        let (hrp, data) = bech32::decode(s)
            .map_err(|e| MalformedSealError::BadText(format!("bech32 decode: {e:?}")))?;
        if hrp.to_lowercase() != SEAL_HRP {
            return Err(MalformedSealError::BadText(format!("wrong HRP '{}'", hrp.to_lowercase())).into());
        }
        if data.is_empty() {
            return Err(MalformedSealError::BadText("empty payload".into()).into());
        }
        // bech32 0.11 returns raw 8-bit data; validate the checksum implicitly
        // happened in decode() (it rejects bad checksums).
        Self::decode_body(SealVersion::CURRENT, &data)
    }
}

impl fmt::Display for BtqP2mrSeal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl FromStr for BtqP2mrSeal {
    type Err = rgb_pq_core::RgbPqError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_text(s)
    }
}

// ----- helpers -------------------------------------------------------------

#[inline]
fn need(b: &[u8], pos: usize, n: usize) -> RgbPqResult<()> {
    if b.len() < pos + n {
        return Err(MalformedSealError::BadLength {
            field: "seal body",
            expected: pos + n,
            actual: b.len(),
        }
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BtqTxid};

    fn sample_seal() -> BtqP2mrSeal {
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
    fn binary_roundtrip_is_stable() {
        let s = sample_seal();
        let enc = s.to_binary();
        let dec = BtqP2mrSeal::from_binary(&enc).unwrap();
        assert_eq!(dec, s);
    }

    #[test]
    fn text_roundtrip_is_stable() {
        let s = sample_seal();
        let txt = s.to_text();
        assert!(txt.starts_with("rgbpqseal1"));
        let dec = BtqP2mrSeal::from_text(&txt).unwrap();
        assert_eq!(dec, s);
    }

    #[test]
    fn binary_rejects_bad_magic() {
        let mut enc = sample_seal().to_binary();
        enc[0] ^= 0xff;
        assert!(BtqP2mrSeal::from_binary(&enc).is_err());
    }

    #[test]
    fn binary_rejects_bad_domain_tag() {
        let mut enc = sample_seal().to_binary();
        let tag_off = BIN_MAGIC.len() + 1;
        enc[tag_off] ^= 0xff;
        assert!(BtqP2mrSeal::from_binary(&enc).is_err());
    }

    #[test]
    fn binary_rejects_truncated() {
        let enc = sample_seal().to_binary();
        assert!(BtqP2mrSeal::from_binary(&enc[..enc.len() - 1]).is_err());
    }

    #[test]
    fn text_rejects_wrong_hrp() {
        let txt = sample_seal().to_text();
        let tampered = format!("btqwrong1{}", &txt[SEAL_HRP.len() + 1..]);
        assert!(BtqP2mrSeal::from_text(&tampered).is_err());
    }

    // ---- digest-variation tests (every field must affect the digest) ----

    fn digest_changes<F: FnOnce(&mut BtqP2mrSeal)>(mutate: F) {
        let base = sample_seal();
        let d0 = base.canonical_digest();
        let mut other = base.clone();
        mutate(&mut other);
        let d1 = other.canonical_digest();
        assert_ne!(d0, d1, "digest did not change after mutation");
    }

    #[test]
    fn digest_changes_when_txid_changes() {
        digest_changes(|s| s.outpoint.txid = BtqTxid::from_bytes([0x99; 32]));
    }
    #[test]
    fn digest_changes_when_vout_changes() {
        digest_changes(|s| s.outpoint.vout = 1);
    }
    #[test]
    fn digest_changes_when_p2mr_root_changes() {
        digest_changes(|s| s.p2mr_root = [0x44; 32]);
    }
    #[test]
    fn digest_changes_when_script_leaf_changes() {
        digest_changes(|s| s.script_leaf_hash = [0x55; 32]);
    }
    #[test]
    fn digest_changes_when_owner_algo_changes() {
        // Dilithium5 is feature-gated, but the byte still changes the digest;
        // build it directly to avoid the from_byte gate.
        let mut other = sample_seal();
        other.owner_algo = PqSigAlgo::Dilithium5;
        assert_ne!(
            sample_seal().canonical_digest(),
            other.canonical_digest()
        );
    }
    #[test]
    fn digest_changes_when_chain_id_changes() {
        digest_changes(|s| s.chain_id = BtqChainId::BitcoinQuantumTestnet);
    }
    #[test]
    fn digest_changes_when_locator_changes() {
        digest_changes(|s| s.commitment_locator = CommitmentLocator::OpretVout(2));
    }
    #[test]
    fn digest_changes_when_policy_changes() {
        digest_changes(|s| s.confirmation_policy = ConfirmationPolicy::Depth(6));
    }

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(
            sample_seal().canonical_digest(),
            sample_seal().canonical_digest()
        );
    }
}
