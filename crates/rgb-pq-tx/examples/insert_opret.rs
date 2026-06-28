//! Throwaway helper: read an unsigned BTQ tx hex from a file (or stdin) and
//! append an RGB-PQ OP_RETURN commitment for a fixed demo seal, printing the
//! modified hex. Used to experimentally validate the insertion + sign + broadcast
//! ordering against a live regtest node.

use std::io::Read;

use rgb_pq_seal::{
    BtqChainId, BtqOutpoint, BtqP2mrSeal, BtqTxid, CommitmentLocator, ConfirmationPolicy, PqSigAlgo,
};
use rgb_pq_tx::append_opret_commitment;

fn main() {
    let mut unsigned = String::new();
    if let Some(path) = std::env::args().nth(1) {
        std::fs::read_to_string(path)
            .unwrap()
            .trim()
            .clone_into(&mut unsigned);
    } else {
        std::io::stdin().read_to_string(&mut unsigned).unwrap();
    }
    let unsigned = unsigned.trim();

    // Demo seal matching the OP_TRUE P2MR funding tx output we created.
    // txid/vout are read from the env so the seal binds to the real outpoint.
    let txid_hex = std::env::var("SEAL_TXID").unwrap_or_else(|_| "00".repeat(32));
    let vout: u32 = std::env::var("SEAL_VOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let root_hex = std::env::var("SEAL_ROOT").unwrap_or_else(|_| "22".repeat(32));
    let leaf_hex = std::env::var("SEAL_LEAF").unwrap_or_else(|_| "33".repeat(32));

    let txid = txid_hex.parse::<BtqTxid>().expect("txid");
    let mut root = [0u8; 32];
    hex::decode_to_slice(&root_hex, &mut root).expect("root");
    let mut leaf = [0u8; 32];
    hex::decode_to_slice(&leaf_hex, &mut leaf).expect("leaf");

    let seal = BtqP2mrSeal::new(
        BtqChainId::BitcoinQuantumRegtest,
        BtqOutpoint::new(txid, vout),
        root,
        leaf,
        PqSigAlgo::Dilithium2,
        CommitmentLocator::OpretFirst,
        ConfirmationPolicy::OneConf,
    );
    let mpc = [0xa5u8; 32];
    let modified = append_opret_commitment(unsigned, &seal, mpc).expect("insert");
    print!("{modified}");
}
