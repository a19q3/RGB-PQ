//! Insert an RGB-PQ OP_RETURN commitment into an unsigned BTQ raw transaction.
//!
//! The closing transaction is produced by BTQ's `createp2mrspend`, which
//! returns an unsigned raw tx containing `[P2MR inputs] -> [recipient,
//! change?]`. RGB requires the closing tx to carry an OP_RETURN output holding
//! the MPC commitment (`rgb-consensus/src/validation/validator.rs:464`), so we
//! **append** an OP_RETURN output carrying the RGB-PQ commitment payload to the
//! unsigned tx, re-encode it, and then hand it to `signp2mrtransaction`.
//!
//! This is deterministic and uses the real `bitcoin` consensus codec, so the
//! resulting hex is byte-identical to what a hand-built tx would be.

use bitcoin::consensus::encode;
use bitcoin::script::PushBytesBuf;
use bitcoin::{Amount, Transaction, TxOut};

use rgb_pq_commit::RgbPqCommitment;
use rgb_pq_core::{CommitmentError, RgbPqResult};
use rgb_pq_seal::BtqP2mrSeal;

/// Append an OP_RETURN output carrying the RGB-PQ commitment for `seal` to the
/// transaction decoded from `unsigned_hex`. Returns the re-encoded hex.
///
/// The OP_RETURN output is appended as the **last** output and uses a 0-sat
/// value (standard for OP_RETURN). The seal's `commitment_locator` is therefore
/// resolved to that final vout by the resolver via `OpretFirst`-style scanning.
pub fn append_opret_commitment(
    unsigned_hex: &str,
    seal: &BtqP2mrSeal,
    mpc: rgb_pq_commit::MpcCommitment,
) -> RgbPqResult<String> {
    let raw = hex::decode(unsigned_hex)
        .map_err(|e| CommitmentError::Malformed(format!("unsigned hex decode: {e}")))?;
    let mut tx: Transaction = encode::deserialize(&raw)
        .map_err(|e| CommitmentError::Malformed(format!("tx deserialize: {e}")))?;

    let payload = RgbPqCommitment::new(seal, mpc).encode();
    let opret_script = build_op_return_script(&payload);
    tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: opret_script,
    });

    let reencoded = encode::serialize(&tx);
    Ok(hex::encode(&reencoded))
}

/// Build an `OP_RETURN <push payload>` scriptPubKey.
pub fn build_op_return_script(payload: &[u8]) -> bitcoin::ScriptBuf {
    let mut buf = PushBytesBuf::new();
    let _ = buf.extend_from_slice(payload);
    bitcoin::script::Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_slice(buf)
        .into_script()
}

/// Scan a *signed* raw tx hex for the RGB-PQ commitment bound to `seal`.
/// Returns the decoded commitment if exactly one valid one is present.
pub fn find_commitment_in_signed_tx(
    signed_hex: &str,
    seal: &BtqP2mrSeal,
) -> RgbPqResult<Option<RgbPqCommitment>> {
    let raw = hex::decode(signed_hex)
        .map_err(|e| CommitmentError::Malformed(format!("signed hex decode: {e}")))?;
    let tx: Transaction = encode::deserialize(&raw)
        .map_err(|e| CommitmentError::Malformed(format!("tx deserialize: {e}")))?;
    let mut hits = Vec::new();
    for (vout, out) in tx.output.iter().enumerate() {
        let spk = out.script_pubkey.as_bytes();
        if let Some(payload) = rgb_pq_commit::strip_op_return(spk) {
            if let Ok(c) = RgbPqCommitment::decode_for(payload, seal) {
                hits.push((vout as u32, c));
            }
        }
    }
    match hits.len() {
        0 => Ok(None),
        1 => Ok(Some(hits.remove(0).1)),
        _ => Err(CommitmentError::Duplicate(signed_hex.to_string()).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
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

    fn sample_unsigned_tx_hex() -> String {
        // Minimal tx with one input (empty) + one output (recipient). Built via
        // the bitcoin codec so it deserialises cleanly.
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([0x11; 32]),
                    0,
                ),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            }],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_raw_hash(
                    bitcoin::hashes::Hash::all_zeros(),
                )),
            }],
        };
        hex::encode(encode::serialize(&tx))
    }

    #[test]
    fn append_inserts_opret_and_roundtrips() {
        let seal = seal();
        let unsigned = sample_unsigned_tx_hex();
        let mpc = [0xa5; 32];
        let with_commit = append_opret_commitment(&unsigned, &seal, mpc).unwrap();

        // The new hex must differ (one more output).
        assert_ne!(unsigned, with_commit);

        // Must be findable again.
        let found = find_commitment_in_signed_tx(&with_commit, &seal).unwrap();
        let c = found.expect("commitment present");
        assert_eq!(c.mpc, mpc);
        assert_eq!(c.chain, BtqChainId::BitcoinQuantumRegtest);
    }

    #[test]
    fn append_rejects_garbage_hex() {
        let seal = seal();
        assert!(append_opret_commitment("nothex!!", &seal, [0u8; 32]).is_err());
    }

    #[test]
    fn find_returns_none_when_absent() {
        let seal = seal();
        let none = find_commitment_in_signed_tx(&sample_unsigned_tx_hex(), &seal).unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn opret_script_starts_with_op_return() {
        let s = build_op_return_script(&[0xaa, 0xbb]);
        let b = s.as_bytes();
        assert_eq!(b[0], 0x6a); // OP_RETURN
        assert_eq!(b[1], 0x02); // push 2 bytes
        assert_eq!(&b[2..4], &[0xaa, 0xbb]);
    }
}
