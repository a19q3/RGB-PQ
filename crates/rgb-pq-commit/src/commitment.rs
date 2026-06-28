//! Deterministic, domain-separated RGB-PQ commitment payload.
//!
//! This is the *visible* payload we write into an OP_RETURN output. It wraps
//! the RGB MPC commitment (32 bytes) together with the metadata needed to
//! unambiguously bind it to a specific BTQ P2MR seal and chain, so that the
//! resolver can detect missing / malformed / duplicate / wrong-chain /
//! wrong-seal commitments structurally, before handing off to RGB consensus.

use sha2::{Digest, Sha256};

use rgb_pq_core::{CommitmentError, Domain, RgbPqResult};
use rgb_pq_seal::{BtqChainId, BtqP2mrSeal};

/// Magic prefixing every RGB-PQ OP_RETURN commitment payload (ASCII `RGBPQCM`).
pub const COMMITMENT_MAGIC: &[u8] = b"RGBPQCM";
/// Protocol tag for the RGB-PQ commitment protocol.
pub const COMMITMENT_PROTOCOL_TAG: &[u8] = b"rgbpq:commitment:v0";

/// A 32-byte RGB MPC commitment (the value RGB's `opret` embeds).
pub type MpcCommitment = [u8; 32];

/// The full RGB-PQ commitment payload written to the OP_RETURN output.
///
/// Layout (deterministic, versioned, domain-separated):
/// ```text
/// MAGIC(7) || TAG(21) || chain(1) || txid(32) || vout(4) || mpc(32) || digest(32)
/// ```
/// where `digest` is the SHA-256 over the domain prefix + seal body, ensuring
/// the commitment is bound to exactly the seal that the transition closes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgbPqCommitment {
    /// The chain this commitment is valid on.
    pub chain: BtqChainId,
    /// The outpoint of the seal being closed (txid in display byte order).
    pub seal_txid: [u8; 32],
    /// The vout of the seal being closed.
    pub seal_vout: u32,
    /// The RGB MPC commitment (the value opret embeds into the scriptPubKey).
    pub mpc: MpcCommitment,
}

impl RgbPqCommitment {
    /// Construct a commitment for a seal and an MPC commitment value.
    pub fn new(seal: &BtqP2mrSeal, mpc: MpcCommitment) -> Self {
        Self {
            chain: seal.chain_id,
            seal_txid: *seal.outpoint.txid.as_bytes(),
            seal_vout: seal.outpoint.vout,
            mpc,
        }
    }

    /// Encode to a deterministic byte payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + 21 + 1 + 32 + 4 + 32 + 32);
        out.extend_from_slice(COMMITMENT_MAGIC);
        out.extend_from_slice(COMMITMENT_PROTOCOL_TAG);
        out.push(self.chain.to_byte());
        out.extend_from_slice(&self.seal_txid);
        out.extend_from_slice(&self.seal_vout.to_le_bytes());
        out.extend_from_slice(&self.mpc);
        out.extend_from_slice(&self.seal_digest());
        out
    }

    /// The domain-separated seal-binding digest (proves this commitment is for
    /// exactly this seal).
    pub fn seal_digest(&self) -> [u8; 32] {
        let mut prefix = Domain::p2mr(self.chain.domain_str()).prefixed();
        prefix.extend_from_slice(&self.seal_txid);
        prefix.extend_from_slice(&self.seal_vout.to_le_bytes());
        let mut h = Sha256::new();
        h.update(prefix);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }

    /// Decode and validate against an expected seal.
    pub fn decode_for(bytes: &[u8], expected: &BtqP2mrSeal) -> RgbPqResult<Self> {
        let c = Self::decode(bytes)?;
        c.verify_against(expected)?;
        Ok(c)
    }

    /// Decode without a seal context (does not validate the binding).
    pub fn decode(bytes: &[u8]) -> RgbPqResult<Self> {
        let magic_len = COMMITMENT_MAGIC.len();
        let tag_len = COMMITMENT_PROTOCOL_TAG.len();
        // chain(1) + txid(32) + vout(4) + mpc(32) + digest(32)
        let body_len = 1 + 32 + 4 + 32 + 32;
        let need = magic_len + tag_len + body_len;
        if bytes.len() != need {
            return Err(CommitmentError::Malformed(format!(
                "commitment payload length {} != {need}",
                bytes.len()
            ))
            .into());
        }
        if &bytes[..magic_len] != COMMITMENT_MAGIC {
            return Err(CommitmentError::Malformed("bad magic".into()).into());
        }
        let tag_end = magic_len + tag_len;
        if &bytes[magic_len..tag_end] != COMMITMENT_PROTOCOL_TAG {
            return Err(CommitmentError::Malformed("bad protocol tag".into()).into());
        }
        let mut pos = tag_end;
        let chain = BtqChainId::from_byte(bytes[pos])?;
        pos += 1;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        let mut vout_buf = [0u8; 4];
        vout_buf.copy_from_slice(&bytes[pos..pos + 4]);
        let vout = u32::from_le_bytes(vout_buf);
        pos += 4;
        let mut mpc = [0u8; 32];
        mpc.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[pos..pos + 32]);
        let c = RgbPqCommitment {
            chain,
            seal_txid: txid,
            seal_vout: vout,
            mpc,
        };
        if digest != c.seal_digest() {
            return Err(CommitmentError::Malformed("seal digest mismatch".into()).into());
        }
        Ok(c)
    }

    /// Validate this commitment against an expected seal: chain and outpoint
    /// must match. (The binding digest is checked at decode time; this method
    /// enforces the seal/chain correspondence that decode cannot.)
    pub fn verify_against(&self, expected: &BtqP2mrSeal) -> RgbPqResult<()> {
        if self.chain != expected.chain_id {
            return Err(CommitmentError::WrongChain.into());
        }
        if self.seal_txid != *expected.outpoint.txid.as_bytes()
            || self.seal_vout != expected.outpoint.vout
        {
            return Err(CommitmentError::WrongSeal.into());
        }
        Ok(())
    }
}

/// Locator for finding the OP_RETURN output in a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitmentPayload {
    /// Found the RGB-PQ commitment in the output at this vout.
    Found {
        /// The vout index of the OP_RETURN output.
        vout: u32,
        /// The decoded commitment.
        commitment: RgbPqCommitment,
    },
    /// Multiple RGB-PQ commitments were found (ambiguous / duplicate).
    Duplicate(Vec<u32>),
    /// No RGB-PQ commitment output was found.
    Missing,
}

impl CommitmentPayload {
    /// Scan a transaction's outputs (as scriptPubKey bytes + vout) for RGB-PQ
    /// commitments. `opret_outputs` is an iterator of `(vout, script_pubkey)`.
    pub fn scan<'a, I>(opret_outputs: I) -> Self
    where
        I: IntoIterator<Item = (u32, &'a [u8])>,
    {
        let mut hits: Vec<(u32, RgbPqCommitment)> = Vec::new();
        for (vout, spk) in opret_outputs {
            if let Some(payload) = strip_op_return(spk) {
                if let Ok(c) = RgbPqCommitment::decode(payload) {
                    hits.push((vout, c));
                }
            }
        }
        match hits.len() {
            0 => CommitmentPayload::Missing,
            1 => CommitmentPayload::Found {
                vout: hits[0].0,
                commitment: hits.remove(0).1,
            },
            _ => CommitmentPayload::Duplicate(hits.into_iter().map(|(v, _)| v).collect()),
        }
    }
}

/// If `spk` is an OP_RETURN script carrying a push of our payload, return the
/// payload slice; otherwise return `None`. An OP_RETURN scriptPubKey is
/// `OP_RETURN (0x6a) [push opcode] [data]`.
pub fn strip_op_return(spk: &[u8]) -> Option<&[u8]> {
    if spk.first() != Some(&0x6a) {
        return None;
    }
    let rest = &spk[1..];
    // Direct push of <=75 bytes: opcode is the length.
    if rest.is_empty() {
        return None;
    }
    let n = rest[0] as usize;
    if n <= 0x4b && rest.len() == 1 + n {
        return Some(&rest[1..]);
    }
    // PUSHDATA1
    if rest[0] == 0x4c && rest.len() >= 2 {
        let n = rest[1] as usize;
        if rest.len() == 2 + n {
            return Some(&rest[2..]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rgb_pq_seal::{
        BtqChainId, BtqOutpoint, BtqP2mrSeal, BtqTxid, CommitmentLocator, ConfirmationPolicy,
        PqSigAlgo,
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
    fn commitment_roundtrip_and_binding() {
        let s = seal();
        let c = RgbPqCommitment::new(&s, [0xa5; 32]);
        let enc = c.encode();
        // MAGIC(7) + TAG(19) + 1 + 32 + 4 + 32 + 32 = 127
        assert_eq!(enc.len(), 127);
        let dec = RgbPqCommitment::decode_for(&enc, &s).unwrap();
        assert_eq!(dec, c);
    }

    #[test]
    fn decode_rejects_wrong_chain() {
        let s = seal();
        let c = RgbPqCommitment::new(&s, [0xa5; 32]);
        let enc = c.encode();
        let mut other = s.clone();
        other.chain_id = BtqChainId::BitcoinQuantumTestnet;
        let err = RgbPqCommitment::decode_for(&enc, &other).unwrap_err();
        assert!(matches!(
            err,
            rgb_pq_core::RgbPqError::Commitment(CommitmentError::WrongChain)
        ));
    }

    #[test]
    fn decode_rejects_wrong_seal() {
        let s = seal();
        let c = RgbPqCommitment::new(&s, [0xa5; 32]);
        let enc = c.encode();
        let mut other = s.clone();
        other.outpoint.vout = 9;
        let err = RgbPqCommitment::decode_for(&enc, &other).unwrap_err();
        assert!(matches!(
            err,
            rgb_pq_core::RgbPqError::Commitment(CommitmentError::WrongSeal)
        ));
    }

    #[test]
    fn decode_rejects_truncated_and_bad_magic() {
        let s = seal();
        let mut enc = RgbPqCommitment::new(&s, [0xa5; 32]).encode();
        assert!(RgbPqCommitment::decode(&enc[..enc.len() - 1]).is_err());
        enc[0] ^= 0xff;
        assert!(RgbPqCommitment::decode(&enc).is_err());
    }

    #[test]
    fn decode_rejects_tampered_digest() {
        let s = seal();
        let mut enc = RgbPqCommitment::new(&s, [0xa5; 32]).encode();
        enc[100] ^= 0x01; // tamper somewhere in mpc
        assert!(RgbPqCommitment::decode_for(&enc, &s).is_err());
    }

    #[test]
    fn scan_finds_commitment() {
        let s = seal();
        let payload = RgbPqCommitment::new(&s, [0xa5; 32]).encode();
        let spk = build_opret_script(&payload);
        match CommitmentPayload::scan([(0u32, spk.as_slice())]) {
            CommitmentPayload::Found { vout, commitment } => {
                assert_eq!(vout, 0);
                assert_eq!(commitment.mpc, [0xa5; 32]);
            }
            _ => panic!("expected found"),
        }
    }

    #[test]
    fn scan_detects_duplicate() {
        let s = seal();
        let payload = RgbPqCommitment::new(&s, [0xa5; 32]).encode();
        let a = build_opret_script(&payload);
        let b = build_opret_script(&payload);
        match CommitmentPayload::scan([(0u32, a.as_slice()), (1u32, b.as_slice())]) {
            CommitmentPayload::Duplicate(vs) => assert_eq!(vs, vec![0, 1]),
            _ => panic!("expected duplicate"),
        }
    }

    #[test]
    fn scan_detects_missing() {
        let spk = vec![0x6a, 0x02, 0xaa, 0xbb]; // OP_RETURN but not ours
        assert!(matches!(
            CommitmentPayload::scan([(0u32, spk.as_slice())]),
            CommitmentPayload::Missing
        ));
        // non-OP_RETURN output ignored
        let spk2 = vec![0x00, 0x14];
        assert!(matches!(
            CommitmentPayload::scan([(0u32, spk2.as_slice())]),
            CommitmentPayload::Missing
        ));
    }

    /// Build a canonical OP_RETURN scriptPubKey carrying `payload` (handles the
    /// push opcode correctly for >75-byte payloads).
    fn build_opret_script(payload: &[u8]) -> Vec<u8> {
        use bitcoin::script::PushBytesBuf;
        let mut buf = PushBytesBuf::new();
        // extend_from_slice on PushBytesBuf returns Result; payloads here are
        // well within the push limit so this cannot fail, but we honour it.
        let _ = buf.extend_from_slice(payload);
        let script = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(buf)
            .into_script();
        script.into_bytes()
    }

    // --- digest-variation tests for the commitment (mirror the seal tests) ---

    #[test]
    fn commitment_changes_when_mpc_changes() {
        let s = seal();
        let a = RgbPqCommitment::new(&s, [0xa5; 32]).encode();
        let b = RgbPqCommitment::new(&s, [0x5a; 32]).encode();
        assert_ne!(a, b);
    }

    #[test]
    fn commitment_changes_when_chain_changes() {
        let s = seal();
        let mut s2 = s.clone();
        s2.chain_id = BtqChainId::BitcoinQuantumTestnet;
        let a = RgbPqCommitment::new(&s, [0xa5; 32]).encode();
        let b = RgbPqCommitment::new(&s2, [0xa5; 32]).encode();
        assert_ne!(a, b);
    }
}
