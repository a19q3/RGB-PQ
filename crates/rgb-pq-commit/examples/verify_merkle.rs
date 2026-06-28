// Verify our Merkle math matches btq-core's 2-leaf tree root.
// Tree: leaf A = OP_TRUE (0x51), leaf B = OP_RETURN 0xdead (6a02dead), both at depth 1.
// Root = ComputeTapbranchHash(Tapleaf(A), Tapleaf(B)).
fn main() {
    let a = rgb_pq_commit::compute_tapleaf_hash(0xc0, &[0x51]);
    let b = rgb_pq_commit::compute_tapleaf_hash(0xc0, &[0x6a, 0x02, 0xde, 0xad]);
    let root = rgb_pq_commit::compute_tapbranch_hash(&a, &b);
    let got = hex::encode(root);
    let want = "518123966a74debdcfb16a12d5f4e299febb35dbb912a8229d4005b05caacba0";
    println!("our_root  = {got}");
    println!("node_root = {want}");
    assert_eq!(got, want, "MERKLE MATH MISMATCH");
    println!("MATCH ✓ — our Merkle math equals btq-core's consensus");
}
