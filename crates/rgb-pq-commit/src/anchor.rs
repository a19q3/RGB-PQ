//! Bridge to RGB's real commitment / anchor types.
//!
//! This module wraps RGB's `EmbedCommitVerify<Commitment, OpretFirst>` impls so
//! the rest of RGB-PQ doesn't have to depend directly on `rgbcore::dbc`. It
//! exposes:
//!   * [`embed_opret_commitment`] — write a 32-byte MPC commitment into the
//!     first OP_RETURN output of a `bitcoin::Transaction` and return RGB's
//!     `OpretProof` (the typed proof the RGB validator checks);
//!   * [`verify_opret_anchor`] — verify an `Anchor<OpretProof>` against a tx,
//!     contract id and bundle id, i.e. reproduce the exact check RGB's
//!     validator performs (`validate_seal_closing`,
//!     `rgb-consensus/src/validation/validator.rs:439`).

use bitcoin::Transaction as Tx;

use rgb_pq_core::CommitmentError;
use rgb_pq_seal::BtqP2mrSeal;

use crate::commitment::{MpcCommitment, RgbPqCommitment};

/// Re-export of RGB's MPC commitment type.
pub use rgbcore::commit_verify::mpc::Commitment as RgbMpcCommitment;
/// Re-export of RGB's OP_RETURN DBC proof.
pub use rgbcore::dbc::opret::OpretProof;
/// Re-export of RGB's anchor over an opret proof.
pub use rgbcore::dbc::Anchor as RgbAnchor;

/// Errors bridging to RGB's anchor types.
#[derive(Debug, thiserror::Error)]
pub enum OpretAnchorError {
    /// The RGB opret embed-commit failed (typically: no OP_RETURN output).
    #[error("opret embed-commit failed: {0}")]
    Embed(String),
    /// RGB anchor verification failed.
    #[error("opret anchor verify failed: {0}")]
    Verify(String),
}

impl From<OpretAnchorError> for rgb_pq_core::RgbPqError {
    fn from(e: OpretAnchorError) -> Self {
        rgb_pq_core::RgbPqError::Commitment(CommitmentError::Malformed(e.to_string()))
    }
}

/// Embed an RGB MPC commitment into the first OP_RETURN output of `tx`,
/// returning RGB's `OpretProof`.
///
/// This is exactly `<Tx as EmbedCommitVerify<Commitment, OpretFirst>>::embed_commit`
/// (`rgb-consensus/src/dbc/opret/tx.rs:44`). The caller must have already
/// added an OP_RETURN output to `tx`.
pub fn embed_opret_commitment(
    tx: &mut Tx,
    mpc: MpcCommitment,
) -> Result<OpretProof, OpretAnchorError> {
    use rgbcore::commit_verify::EmbedCommitVerify;
    use rgbcore::dbc::opret::OpretFirst;
    let commitment = RgbMpcCommitment::copy_from_slice(&mpc)
        .map_err(|e| OpretAnchorError::Embed(e.to_string()))?;
    // RGB's EmbedCommitVerify for Tx under OpretFirst.
    <Tx as EmbedCommitVerify<RgbMpcCommitment, OpretFirst>>::embed_commit(tx, &commitment)
        .map_err(|e| OpretAnchorError::Embed(e.to_string()))
}

/// Verify an RGB `Anchor<OpretProof>` against a tx, contract id and bundle id.
///
/// Reproduces the RGB validator's two-step check:
///   1. `anchor.convolve(contract_id, bundle_id)` -> MPC commitment;
///   2. `anchor.dbc_proof.verify(commitment, &tx)` -> the OP_RETURN carries it.
pub fn verify_opret_anchor(
    anchor: &RgbAnchor<OpretProof>,
    tx: &Tx,
    contract_id: [u8; 32],
    bundle_id: [u8; 32],
) -> Result<(), OpretAnchorError> {
    use rgbcore::commit_verify::mpc::{Message, ProtocolId};
    use rgbcore::dbc::Proof as _;
    let pid = ProtocolId::copy_from_slice(&contract_id)
        .map_err(|e| OpretAnchorError::Verify(e.to_string()))?;
    let msg = Message::copy_from_slice(&bundle_id)
        .map_err(|e| OpretAnchorError::Verify(e.to_string()))?;
    let commitment = anchor
        .convolve(pid, msg)
        .map_err(|e| OpretAnchorError::Verify(format!("convolve: {e:?}")))?;
    anchor
        .dbc_proof
        .verify(&commitment, tx)
        .map_err(|e| OpretAnchorError::Verify(format!("dbc verify: {e:?}")))
}

/// Build the full RGB-PQ OP_RETURN payload for a seal + MPC commitment, ready
/// to be placed in the closing transaction's OP_RETURN output.
pub fn build_opret_payload(seal: &BtqP2mrSeal, mpc: MpcCommitment) -> Vec<u8> {
    RgbPqCommitment::new(seal, mpc).encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Amount;
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

    fn empty_tx_with_opreturn() -> Tx {
        // RGB's opret embed_commit requires an *empty* OP_RETURN output
        // (just the OP_RETURN opcode, 1 byte). It then writes
        // `OP_RETURN PUSH32 <commitment>` into it.
        let spk = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .into_script();
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: Amount::ZERO,
                script_pubkey: spk,
            }],
        }
    }

    #[test]
    fn embed_and_roundtrip_payload_in_opreturn() {
        // Embed an RGB MPC commitment into the OP_RETURN via RGB's real
        // embed_commit, then confirm the script is now exactly
        // `OP_RETURN PUSH32 <commitment>` (34 bytes).
        let mpc = [0x42u8; 32];

        let mut tx = empty_tx_with_opreturn();
        let _proof = embed_opret_commitment(&mut tx, mpc).expect("embed");

        let spk = tx.output[0].script_pubkey.as_bytes();
        assert_eq!(spk[0], 0x6a); // OP_RETURN
        assert_eq!(spk[1], 0x20); // PUSH32
        assert_eq!(&spk[2..34], &mpc);
        assert_eq!(spk.len(), 34);
    }

    #[test]
    fn build_payload_matches_encode() {
        let s = seal();
        let mpc = [0x42u8; 32];
        let a = build_opret_payload(&s, mpc);
        let b = RgbPqCommitment::new(&s, mpc).encode();
        assert_eq!(a, b);
    }

    #[test]
    fn embed_fails_without_opreturn_output() {
        // A tx whose only output is NOT an OP_RETURN must be rejected by RGB's
        // embed_commit (it returns NoOpretOutput).
        let spk = bitcoin::ScriptBuf::from_hex("5120").unwrap(); // truncated p2tr-ish, not opret
        let mut tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: spk,
            }],
        };
        assert!(embed_opret_commitment(&mut tx, [0u8; 32]).is_err());
    }
}
