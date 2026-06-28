//! Build a real P2MR-ret tree and print the leaf scripts + Rust-computed root.
fn main() {
    use rgb_pq_commit::{build_p2mr_ret_tree_for_seal, commitment_leaf_script};
    use rgb_pq_seal::BtqChainId;
    let chain = BtqChainId::BitcoinQuantumRegtest;
    let mpc = [0xa5; 32];
    let pq_leaf = vec![0x51]; // OP_TRUE
    let tree = build_p2mr_ret_tree_for_seal(chain, mpc, &pq_leaf);
    let comm_script = commitment_leaf_script(chain, mpc);
    println!("PQ_LEAF_HEX={}", hex::encode(&pq_leaf));
    println!("COMM_LEAF_HEX={}", hex::encode(&comm_script));
    println!("RUST_ROOT={}", hex::encode(tree.root));
}
