//! Supporting types for the [`crate::BtqP2mrSeal`].
//!
//! These are the small, consensus-relevant primitives that compose a BTQ P2MR
//! single-use seal. Each is independently serialisable and individually
//! testable.

use core::fmt;
use core::str::FromStr;

use bitcoin::hashes::Hash;
use rgb_pq_core::{
    ChainConfusion, MalformedSealError, OwnerAlgoError, RgbPqResult, UnsupportedFeature,
};

// =========================================================================
// Chain id
// =========================================================================

/// A BTQ chain identifier.
///
/// Only Bitcoin Quantum **regtest** and **testnet** are supported. Mainnet is
/// explicitly rejected by this type's parser — RGB-PQ never targets mainnet.
/// There is no implicit default network: a `BtqChainId` must always be supplied
/// when constructing a seal.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum BtqChainId {
    /// Bitcoin Quantum regtest. HRP for P2MR addresses: `qcrt`.
    BitcoinQuantumRegtest = 0x01,
    /// Bitcoin Quantum testnet. HRP for P2MR addresses: `tbtq`.
    BitcoinQuantumTestnet = 0x02,
}

impl BtqChainId {
    /// The canonical domain-separation chain string, used in every digest.
    pub fn domain_str(self) -> &'static str {
        match self {
            BtqChainId::BitcoinQuantumRegtest => "bitcoin-quantum-regtest",
            BtqChainId::BitcoinQuantumTestnet => "bitcoin-quantum-testnet",
        }
    }

    /// The bech32m HRP used for P2MR addresses on this chain (mirrors
    /// `btq-core`'s `Bech32HRP()`).
    pub fn p2mr_hrp(self) -> &'static str {
        match self {
            BtqChainId::BitcoinQuantumRegtest => "qcrt",
            BtqChainId::BitcoinQuantumTestnet => "tbtq",
        }
    }

    /// Encode as a single byte (binary serialisation).
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Decode from a single byte.
    pub fn from_byte(b: u8) -> RgbPqResult<Self> {
        match b {
            0x01 => Ok(BtqChainId::BitcoinQuantumRegtest),
            0x02 => Ok(BtqChainId::BitcoinQuantumTestnet),
            _ => Err(ChainConfusion::UnknownChainId.into()),
        }
    }

    /// Parse a `BtqChainId` from its canonical domain string.
    pub fn from_domain_str(s: &str) -> RgbPqResult<Self> {
        match s {
            "bitcoin-quantum-regtest" => Ok(BtqChainId::BitcoinQuantumRegtest),
            "bitcoin-quantum-testnet" => Ok(BtqChainId::BitcoinQuantumTestnet),
            "bitcoin-mainnet" | "mainnet" => Err(ChainConfusion::BitcoinMainnet.into()),
            "bitcoin-testnet" | "testnet3" | "testnet4" | "signet" | "regtest" => {
                Err(ChainConfusion::NonBtqBitcoin(s.to_string()).into())
            }
            other => Err(ChainConfusion::UnsupportedChain(other.to_string()).into()),
        }
    }
}

impl fmt::Display for BtqChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.domain_str())
    }
}

impl FromStr for BtqChainId {
    type Err = rgb_pq_core::RgbPqError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_domain_str(s)
    }
}

// =========================================================================
// Seal version
// =========================================================================

/// Seal encoding version.
///
/// Bumped only on an incompatible change to the binary or textual encoding.
/// Unknown future versions are rejected on parse, never silently accepted.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SealVersion {
    /// The initial production encoding (`rgbpq:v0`).
    V0 = 0x00,
}

impl SealVersion {
    /// Current version constant.
    pub const CURRENT: SealVersion = SealVersion::V0;

    /// Encode as a single byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Decode from a single byte. Unknown versions are rejected.
    pub fn from_byte(b: u8) -> RgbPqResult<Self> {
        match b {
            0x00 => Ok(SealVersion::V0),
            other => Err(MalformedSealError::UnknownVersion(other).into()),
        }
    }
}

impl Default for SealVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl fmt::Display for SealVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealVersion::V0 => f.write_str("v0"),
        }
    }
}

// =========================================================================
// Post-quantum signature algorithm
// =========================================================================

/// A supported post-quantum ownership algorithm for a P2MR leaf.
///
/// **secp256k1 is deliberately absent.** A secp256k1 ownership path can never
/// be constructed as a `PqSigAlgo`; code that requires post-quantum ownership
/// takes this type and therefore cannot silently downgrade.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PqSigAlgo {
    /// CRYSTALS-Dilithium2 (FIPS 204). pk 1312 B, sig 2420 B.
    Dilithium2 = 0x01,
    /// CRYSTALS-Dilithium5 (FIPS 204). pk 2592 B, sig 4627 B.
    /// Available only behind the `dilithium5` feature gate.
    Dilithium5 = 0x02,
}

impl PqSigAlgo {
    /// Encode as a single byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Decode from a single byte. Rejects secp256k1 and unknown algorithms.
    #[cfg(feature = "dilithium5")]
    pub fn from_byte(b: u8) -> RgbPqResult<Self> {
        match b {
            0x01 => Ok(PqSigAlgo::Dilithium2),
            0x02 => Ok(PqSigAlgo::Dilithium5),
            _ => Err(OwnerAlgoError::UnsupportedAlgo(b).into()),
        }
    }

    /// Decode from a single byte. `Dilithium5` requires the `dilithium5`
    /// feature; without it, that byte is rejected as feature-gated.
    #[cfg(not(feature = "dilithium5"))]
    pub fn from_byte(b: u8) -> RgbPqResult<Self> {
        match b {
            0x01 => Ok(PqSigAlgo::Dilithium2),
            0x02 => Err(OwnerAlgoError::FeatureGated("dilithium5".into()).into()),
            _ => Err(OwnerAlgoError::UnsupportedAlgo(b).into()),
        }
    }

    /// Human-readable algorithm name.
    pub fn name(self) -> &'static str {
        match self {
            PqSigAlgo::Dilithium2 => "dilithium2",
            PqSigAlgo::Dilithium5 => "dilithium5",
        }
    }

    /// The size in bytes of a public key for this algorithm (matches
    /// `btq-core` `src/crypto/dilithium_key.h`).
    pub fn pk_len(self) -> usize {
        match self {
            PqSigAlgo::Dilithium2 => 1312,
            PqSigAlgo::Dilithium5 => 2592,
        }
    }

    /// The size in bytes of a signature for this algorithm.
    pub fn sig_len(self) -> usize {
        match self {
            PqSigAlgo::Dilithium2 => 2420,
            PqSigAlgo::Dilithium5 => 4627,
        }
    }

    /// The expected BTQ opcode for a single-key Dilithium checksig leaf
    /// (`OP_CHECKSIGDILITHIUM = 0xbb`).
    pub const CHECKSIG_OPCODE: u8 = 0xbb;
}

impl fmt::Display for PqSigAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =========================================================================
// Commitment locator
// =========================================================================

/// Where, within the closing transaction, the RGB transition commitment
/// (OP_RETURN) is located.
///
/// The locator is part of the canonical seal encoding so the resolver can find
/// the commitment unambiguously and reject duplicate / conflicting commitments.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CommitmentLocator {
    /// The commitment is in the OP_RETURN output at the given vout index.
    OpretVout(u32),
    /// The commitment is in the *first* OP_RETURN output of the tx (the
    /// default RGB opret convention).
    OpretFirst,
}

impl CommitmentLocator {
    /// Tag byte used in the binary encoding.
    const TAG_OPRET_VOUT: u8 = 0x01;
    const TAG_OPRET_FIRST: u8 = 0x02;

    /// Resolve to a concrete vout if possible.
    pub fn resolve_vout(self, opret_vouts: &[u32]) -> Option<u32> {
        match self {
            CommitmentLocator::OpretVout(v) => Some(v),
            CommitmentLocator::OpretFirst => opret_vouts.first().copied(),
        }
    }

    /// Encode to a byte vector.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            CommitmentLocator::OpretVout(v) => {
                let mut out = Vec::with_capacity(5);
                out.push(Self::TAG_OPRET_VOUT);
                out.extend_from_slice(&v.to_le_bytes());
                out
            }
            CommitmentLocator::OpretFirst => vec![Self::TAG_OPRET_FIRST],
        }
    }

    /// Decode from a byte slice of known length.
    pub fn decode(bytes: &[u8]) -> RgbPqResult<(Self, usize)> {
        let Some(&tag) = bytes.first() else {
            return Err(MalformedSealError::BadEncoding("empty locator".into()).into());
        };
        match tag {
            Self::TAG_OPRET_FIRST => Ok((CommitmentLocator::OpretFirst, 1)),
            Self::TAG_OPRET_VOUT => {
                if bytes.len() < 1 + 4 {
                    return Err(MalformedSealError::BadLength {
                        field: "commitment_locator",
                        expected: 5,
                        actual: bytes.len(),
                    }
                    .into());
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&bytes[1..5]);
                Ok((CommitmentLocator::OpretVout(u32::from_le_bytes(buf)), 5))
            }
            other => Err(UnsupportedFeature::CommitmentLocator(format!("tag {other:#x}")).into()),
        }
    }
}

impl Default for CommitmentLocator {
    fn default() -> Self {
        CommitmentLocator::OpretFirst
    }
}

// =========================================================================
// Confirmation / finality policy
// =========================================================================

/// Confirmation / finality policy for considering a seal closed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConfirmationPolicy {
    /// The seal is closed as soon as the spending tx is confirmed (1 conf).
    OneConf,
    /// Require at least `N` confirmations.
    Depth(u32),
}

impl ConfirmationPolicy {
    const TAG_ONE_CONF: u8 = 0x01;
    const TAG_DEPTH: u8 = 0x02;

    /// The minimum number of confirmations required by this policy.
    pub fn required_depth(self) -> u32 {
        match self {
            ConfirmationPolicy::OneConf => 1,
            ConfirmationPolicy::Depth(n) => n.max(1),
        }
    }

    /// Encode to a byte vector.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ConfirmationPolicy::OneConf => vec![Self::TAG_ONE_CONF],
            ConfirmationPolicy::Depth(n) => {
                let mut out = Vec::with_capacity(5);
                out.push(Self::TAG_DEPTH);
                out.extend_from_slice(&n.to_le_bytes());
                out
            }
        }
    }

    /// Decode from a byte slice.
    pub fn decode(bytes: &[u8]) -> RgbPqResult<(Self, usize)> {
        let Some(&tag) = bytes.first() else {
            return Err(MalformedSealError::BadEncoding("empty policy".into()).into());
        };
        match tag {
            Self::TAG_ONE_CONF => Ok((ConfirmationPolicy::OneConf, 1)),
            Self::TAG_DEPTH => {
                if bytes.len() < 1 + 4 {
                    return Err(MalformedSealError::BadLength {
                        field: "confirmation_policy",
                        expected: 5,
                        actual: bytes.len(),
                    }
                    .into());
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&bytes[1..5]);
                Ok((ConfirmationPolicy::Depth(u32::from_le_bytes(buf)), 5))
            }
            other => Err(UnsupportedFeature::CommitmentLocator(format!(
                "policy tag {other:#x}"
            ))
            .into()),
        }
    }
}

impl Default for ConfirmationPolicy {
    fn default() -> Self {
        ConfirmationPolicy::OneConf
    }
}

// =========================================================================
// Outpoint (BTQ = same shape as bitcoin::OutPoint)
// =========================================================================

/// A BTQ outpoint. Mirrors `bitcoin::OutPoint` but is a distinct type so it
/// cannot be confused with a Bitcoin outpoint at the type level.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BtqOutpoint {
    /// The txid.
    pub txid: BtqTxid,
    /// The output index.
    pub vout: u32,
}

impl BtqOutpoint {
    /// Construct from a 32-byte txid and a vout.
    pub fn new(txid: BtqTxid, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// Construct from a `bitcoin::OutPoint` (boundary conversion; the caller
    /// asserts this is a BTQ outpoint).
    pub fn from_bitcoin(o: bitcoin::OutPoint) -> Self {
        Self {
            txid: BtqTxid(o.txid.to_byte_array()),
            vout: o.vout,
        }
    }

    /// Convert to a `bitcoin::OutPoint` (boundary conversion).
    pub fn to_bitcoin(self) -> Option<bitcoin::OutPoint> {
        let txid = bitcoin::Txid::from_byte_array(self.txid.0);
        Some(bitcoin::OutPoint { txid, vout: self.vout })
    }
}

/// A BTQ txid: 32 bytes in display (rev) byte order, matching Bitcoin.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BtqTxid(#[cfg_attr(feature = "serde", serde(with = "txid_serde"))] pub [u8; 32]);

impl BtqTxid {
    /// Construct from raw inner bytes (display order).
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// The inner bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for BtqTxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Bitcoin txids are displayed in reversed byte order.
        for b in self.0.iter().rev() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for BtqTxid {
    type Err = rgb_pq_core::RgbPqError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(MalformedSealError::BadEncoding(format!(
                "txid hex length {} != 64",
                s.len()
            ))
            .into());
        }
        let mut inner = [0u8; 32];
        for i in 0..32 {
            let b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| MalformedSealError::BadEncoding("txid hex".into()))?;
            // reverse into inner (display -> inner)
            inner[31 - i] = b;
        }
        Ok(BtqTxid(inner))
    }
}

#[cfg(feature = "serde")]
mod txid_serde {
    use super::BtqTxid;
    pub fn serialize<S: serde::Serializer>(v: &BtqTxid, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(v)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<BtqTxid, D::Error> {
        use core::str::FromStr;
        let s = String::deserialize(d)?;
        BtqTxid::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_id_rejects_mainnet() {
        assert!(BtqChainId::from_domain_str("bitcoin-mainnet").is_err());
        assert!(BtqChainId::from_domain_str("mainnet").is_err());
    }

    #[test]
    fn chain_id_rejects_non_btq_bitcoin() {
        for s in ["regtest", "testnet3", "testnet4", "signet", "bitcoin-testnet"] {
            assert!(BtqChainId::from_domain_str(s).is_err(), "{s} should be rejected");
        }
    }

    #[test]
    fn chain_id_accepts_btq() {
        assert_eq!(
            BtqChainId::from_domain_str("bitcoin-quantum-regtest").unwrap(),
            BtqChainId::BitcoinQuantumRegtest
        );
        assert_eq!(
            BtqChainId::from_domain_str("bitcoin-quantum-testnet").unwrap(),
            BtqChainId::BitcoinQuantumTestnet
        );
    }

    #[test]
    fn p2mr_hrp_matches_btq_core() {
        assert_eq!(BtqChainId::BitcoinQuantumRegtest.p2mr_hrp(), "qcrt");
        assert_eq!(BtqChainId::BitcoinQuantumTestnet.p2mr_hrp(), "tbtq");
    }

    #[test]
    fn pq_algo_sizes_match_btq_core() {
        // btq-core src/crypto/dilithium_key.h
        assert_eq!(PqSigAlgo::Dilithium2.pk_len(), 1312);
        assert_eq!(PqSigAlgo::Dilithium2.sig_len(), 2420);
        assert_eq!(PqSigAlgo::Dilithium5.pk_len(), 2592);
        assert_eq!(PqSigAlgo::Dilithium5.sig_len(), 4627);
    }

    #[test]
    #[cfg(not(feature = "dilithium5"))]
    fn dilithium5_requires_feature_gate() {
        let e = PqSigAlgo::from_byte(0x02).unwrap_err();
        assert!(matches!(
            e,
            rgb_pq_core::RgbPqError::Seal(rgb_pq_core::SealError::OwnerAlgo(
                rgb_pq_core::OwnerAlgoError::FeatureGated(_)
            ))
        ));
    }

    #[test]
    fn pq_algo_rejects_unknown() {
        assert!(PqSigAlgo::from_byte(0x00).is_err());
        assert!(PqSigAlgo::from_byte(0xff).is_err());
    }

    #[test]
    fn commitment_locator_roundtrip() {
        for loc in [
            CommitmentLocator::OpretFirst,
            CommitmentLocator::OpretVout(0),
            CommitmentLocator::OpretVout(7),
            CommitmentLocator::OpretVout(u32::MAX),
        ] {
            let enc = loc.encode();
            let (dec, n) = CommitmentLocator::decode(&enc).unwrap();
            assert_eq!(dec, loc);
            assert_eq!(n, enc.len());
        }
    }

    #[test]
    fn confirmation_policy_roundtrip() {
        for p in [
            ConfirmationPolicy::OneConf,
            ConfirmationPolicy::Depth(1),
            ConfirmationPolicy::Depth(6),
            ConfirmationPolicy::Depth(u32::MAX),
        ] {
            let enc = p.encode();
            let (dec, n) = ConfirmationPolicy::decode(&enc).unwrap();
            assert_eq!(dec, p);
            assert_eq!(n, enc.len());
        }
    }

    #[test]
    fn seal_version_rejects_unknown() {
        assert!(SealVersion::from_byte(0x01).is_err());
        assert_eq!(SealVersion::from_byte(0x00).unwrap(), SealVersion::V0);
    }

    #[test]
    fn txid_display_roundtrip() {
        let inner = [0xaa; 32];
        let t = BtqTxid(inner);
        let s = t.to_string();
        // reversed
        assert_eq!(s, "aa".repeat(32));
        let t2 = BtqTxid::from_str(&s).unwrap();
        assert_eq!(t2, t);
    }
}
