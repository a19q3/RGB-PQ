//! RGB-PQ local end-to-end test crate (Components 10, 13).
//!
//! This crate exercises the full local flow described in `ARCHITECTURE.md` and
//! the brief's "Required local end-to-end behaviour". It has two modes:
//!
//! 1. **Live** — when a `btqd` regtest node is reachable (its RPC URL is given
//!    via `RGBPQ_BTQ_RPC` and optional `RGBPQ_BTQ_USER`/`RGBPQ_BTQ_PASS`), the
//!    flow drives the real BTQ node: create Dilithium keys, fund a P2MR seal,
//!    issue a real RGB asset to it, close the seal, anchor the commitment,
//!    mine, resolve, and verify.
//!
//! 2. **Offline (deterministic)** — when no node is reachable, the flow still
//!    runs every component that does not need a live chain: real RGB NIA
//!    issuance to a BTQ P2MR seal, canonical seal encoding/decoding,
//!    commitment binding/verification, and resolver verification against
//!    deterministic fixtures. The run report states the live node was not
//!    exercised.
//!
//! Both modes are deterministic and run from `cargo test`. The
//! `scripts/e2e-local.sh` wrapper builds/starts `btqd` and runs the live mode.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;

use bitcoin::Txid;
use rgb_pq_chain::{BtqRpcClient, BtqRpcConfig};
use rgb_pq_commit::{MpcCommitment, RgbPqCommitment};
use rgb_pq_resolver::{verify_commitment_in_outputs, CommitmentScan};
use rgb_pq_rgb::{chain_net_for, issue_nia_to_btq_seal, DemoAssetSpec};
use rgb_pq_seal::{
    BtqChainId, BtqOutpoint, BtqP2mrSeal, BtqTxid, CommitmentLocator, ConfirmationPolicy, PqSigAlgo,
};

/// Where the vendored NIA kit lives (relative to the workspace root).
pub fn nia_kit_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../external/rgb-schemas/schemata/NonInflatableAsset.rgb")
}

/// A fixed, deterministic demo seal used by the offline path.
pub fn demo_seal() -> BtqP2mrSeal {
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

/// Configuration discovered from the environment for the live path.
pub struct LiveConfig {
    /// RPC config, if a node is reachable.
    pub rpc: Option<BtqRpcConfig>,
}

/// Read the live configuration from the environment.
pub fn read_live_config() -> LiveConfig {
    let url = env::var("RGBPQ_BTQ_RPC").ok();
    let chain = env::var("RGBPQ_BTQ_CHAIN")
        .ok()
        .and_then(|s| s.parse::<BtqChainId>().ok())
        .unwrap_or(BtqChainId::BitcoinQuantumRegtest);
    match url {
        Some(url) => {
            let user = env::var("RGBPQ_BTQ_USER").unwrap_or_else(|_| "btq".into());
            let pass = env::var("RGBPQ_BTQ_PASS").unwrap_or_else(|_| "btqpass".into());
            let mut cfg = BtqRpcConfig {
                chain,
                url,
                auth: rgb_pq_chain::BtqAuth::UserPass { user, pass },
                timeout_secs: Some(15),
                retries: Some(1),
            };
            let _ = &mut cfg;
            LiveConfig { rpc: Some(cfg) }
        }
        None => LiveConfig { rpc: None },
    }
}

/// Check whether the configured node is actually reachable + on the right
/// chain. Returns the client if so.
pub fn try_connect(cfg: &LiveConfig) -> Option<BtqRpcClient> {
    let rpc = cfg.rpc.as_ref()?;
    let client = BtqRpcClient::new(rpc.clone());
    match client.verify_network() {
        Ok(()) => {
            println!("[e2e] connected to BTQ node on {}", rpc.chain);
            Some(client)
        }
        Err(e) => {
            println!("[e2e] BTQ node reachable but wrong network: {e}");
            None
        }
    }
}

/// Run the offline (deterministic) sub-flow. Exercises every component that
/// does not require a live chain. Returns the count of verified steps.
pub fn run_offline_flow() -> usize {
    let mut steps = 0;

    // 6. issue a demo RGB asset to the BTQ P2MR seal (REAL RGB issuance).
    let kit = nia_kit_path();
    if !kit.exists() {
        panic!(
            "NIA kit missing at {}; run scripts/setup-external.sh first",
            kit.display()
        );
    }
    let txid: Txid = "14295d5bb1a191cdb6286dc0944df938421e3dfcbf0811353ccac4100c2068c5"
        .parse()
        .unwrap();
    let issued = issue_nia_to_btq_seal(
        &kit,
        chain_net_for(&demo_seal()),
        DemoAssetSpec::demo(),
        txid,
        0,
    )
    .expect("RGB NIA issuance must succeed");
    steps += 1;
    println!("[e2e] issued real NIA contract: {}", issued.contract_id);

    // 7. canonical seal encoding round-trips (Component 1).
    let seal = demo_seal();
    let bin = seal.to_binary();
    let dec = BtqP2mrSeal::from_binary(&bin).unwrap();
    assert_eq!(dec, seal);
    let txt = seal.to_text();
    let dec2 = BtqP2mrSeal::from_text(&txt).unwrap();
    assert_eq!(dec2, seal);
    steps += 1;
    println!("[e2e] seal encoding round-trips: {txt}");

    // 8. commitment binding (Component 7): build + verify against the seal.
    let mpc: MpcCommitment = [0xa5; 32];
    let payload = RgbPqCommitment::new(&seal, mpc).encode();
    let decoded = RgbPqCommitment::decode_for(&payload, &seal).unwrap();
    assert_eq!(decoded.mpc, mpc);
    steps += 1;
    println!(
        "[e2e] commitment bound + verified ({} bytes)",
        payload.len()
    );

    // 9. resolver verifies the commitment present in (synthetic) outputs
    //    (Component 6).
    use bitcoin::script::PushBytesBuf;
    let mut pb = PushBytesBuf::new();
    let _ = pb.extend_from_slice(&payload);
    let spk = bitcoin::script::Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_slice(pb)
        .into_script()
        .into_bytes();
    let scan = verify_commitment_in_outputs(&seal, [(0u32, spk.as_slice())]).unwrap();
    assert!(matches!(scan, CommitmentScan::Found));
    steps += 1;
    println!("[e2e] resolver detected valid commitment in closing tx outputs");

    // 10. domain separation: digest changes with chain (Component 2).
    let mut other = seal.clone();
    other.chain_id = BtqChainId::BitcoinQuantumTestnet;
    assert_ne!(seal.canonical_digest(), other.canonical_digest());
    steps += 1;
    println!("[e2e] domain separation holds (regtest != testnet digest)");

    steps
}

/// Print a clear success summary.
pub fn print_summary(mode: &str, steps: usize) {
    println!();
    println!("============================================================");
    println!(" RGB-PQ local end-to-end: SUCCESS ({mode})");
    println!(" verified steps: {steps}");
    println!("============================================================");
}
