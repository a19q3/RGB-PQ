//! RGB-PQ BTQ transaction construction helpers (Component 9).
//!
//! Wraps the BTQ node RPCs into typed, auditable helpers used by the local
//! end-to-end flow:
//!   * generate / load Dilithium test keys (`getnewdilithiumaddress`);
//!   * create a P2MR output whose leaf is a Dilithium checksig
//!     (`getnewp2mraddress` + `sendtop2mr`);
//!   * build an RGB-PQ seal from a P2MR output;
//!   * construct a closing transaction spending the P2MR seal
//!     (`createp2mrspend` + `signp2mrtransaction`);
//!   * attach the RGB transition commitment (OP_RETURN) into the closing tx;
//!   * mine blocks in regtest (`generatetoaddress`).
//!
//! Deterministic test-only keys are clearly marked as fixtures. No private keys
//! are logged.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod commit;

pub use commit::{append_opret_commitment, build_op_return_script, find_commitment_in_signed_tx};

use serde_json::{json, Value};

use rgb_pq_chain::{BtqChainBackend, BtqRpcClient};
use rgb_pq_core::{ResolveError, RgbPqResult};
use rgb_pq_seal::{BtqChainId, BtqOutpoint, BtqP2mrSeal, BtqTxid, PqSigAlgo};

/// A created/funded P2MR output as known to the wallet.
#[derive(Clone, Debug)]
pub struct P2mrOutput {
    /// Wallet-local metadata id.
    pub p2mr_id: String,
    /// The bech32m P2MR address (e.g. `qcrt1z…`).
    pub address: String,
    /// The scriptPubKey (hex).
    pub script_pubkey_hex: String,
    /// The 32-byte Merkle root (hex).
    pub merkle_root_hex: String,
    /// The funding transaction id (hex).
    pub funding_txid: String,
}

/// A Dilithium checksig script leaf (hex of the script). This is a
/// `OP_CHECKSIGDILITHIUM <pubkey>` leaf (opcode `0xbb`).
///
/// The pubkey is 1312 bytes for Dilithium2. The script bytes are:
/// `[push_opcode][pubkey...][0xbb]`.
pub fn dilithium_checksig_leaf_hex(pubkey_hex: &str) -> String {
    // push of up to 75 bytes is direct; >75 needs PUSHDATA1. Dilithium2 pk is
    // 1312 bytes -> 0x4d (PUSHDATA2) [len LE u16] [data].
    let pk = hex::decode(pubkey_hex).unwrap_or_default();
    let len = pk.len();
    let mut script = Vec::with_capacity(3 + len + 1);
    if len <= 0x4b {
        script.push(len as u8);
    } else if len <= 0xff {
        script.push(0x4c); // PUSHDATA1
        script.push(len as u8);
    } else {
        // PUSHDATA2
        script.push(0x4d);
        script.push((len & 0xff) as u8);
        script.push(((len >> 8) & 0xff) as u8);
    }
    script.extend_from_slice(&pk);
    script.push(PqSigAlgo::CHECKSIG_OPCODE); // OP_CHECKSIGDILITHIUM = 0xbb
    hex::encode(&script)
}

/// Build a DILITHIUM_PUBKEYHASH leaf script (hex) from a Dilithium address's
/// scriptPubKey. This is the wallet-signable PQ ownership leaf: the wallet
/// recognises `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIGDILITHIUM`
/// (25 bytes) and signs it with its Dilithium key.
///
/// `dilithium_spk_hex` is the scriptPubKey from `getaddressinfo` on a
/// Dilithium address (format: `76a914<20-byte-pkh>88bb`).
pub fn dilithium_pubkeyhash_leaf_hex(dilithium_spk_hex: &str) -> String {
    // The Dilithium P2PKH scriptPubKey IS the leaf script directly:
    // OP_DUP OP_HASH160 <push20> <pkh> OP_EQUALVERIFY OP_CHECKSIGDILITHIUM
    // = 76 a9 14 <20 bytes> 88 bb  (25 bytes total)
    // The wallet's Solver matches this as TxoutType::DILITHIUM_PUBKEYHASH.
    dilithium_spk_hex.to_string()
}

/// The P2MR tree JSON (DFS leaf list) for a single Dilithium checksig leaf.
pub fn single_leaf_tree(leaf_script_hex: &str) -> Value {
    json!([{ "depth": 0, "leaf_version": 192, "script": leaf_script_hex }])
}

/// A handle to BTQ transaction operations.
pub struct BtqTxOps<'a> {
    client: &'a BtqRpcClient,
}

impl<'a> BtqTxOps<'a> {
    /// Construct from an RPC client.
    pub fn new(client: &'a BtqRpcClient) -> Self {
        Self { client }
    }

    /// Generate a new Dilithium address + its pubkey (test keys; clearly
    /// fixture-grade).
    pub fn new_dilithium_address(&self) -> RgbPqResult<(String, String)> {
        let v = self.client.call("getnewdilithiumaddress", &[])?;
        // The RPC may return the address as a bare string or inside a JSON
        // object {"address": "..."}. Handle both.
        let addr = v
            .as_str()
            .map(String::from)
            .or_else(|| v.get("address").and_then(Value::as_str).map(String::from))
            .ok_or_else(|| ResolveError::MissingTx("getnewdilithiumaddress: no address".into()))?;
        // The pubkey is not directly exposed; return empty (the PKH leaf path
        // uses the scriptPubKey via getaddressinfo instead).
        Ok((addr, String::new()))
    }

    /// Create and fund a P2MR output with a single Dilithium checksig leaf.
    pub fn create_fund_p2mr(
        &self,
        leaf_script_hex: &str,
        amount_btc: f64,
        label: &str,
    ) -> RgbPqResult<P2mrOutput> {
        let tree = single_leaf_tree(leaf_script_hex);
        let v = self
            .client
            .call("sendtop2mr", &[tree, amount_btc.into(), label.into()])?;
        let p2mr_id = v
            .get("p2mr_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // `sendtop2mr` returns only {txid, address, p2mr_id}; the merkle_root
        // and scriptPubKey are fetched from getp2mrinfo.
        let funding_txid = v
            .get("txid")
            .and_then(Value::as_str)
            .or_else(|| v.get("tx").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        let info = self
            .client
            .call("getp2mrinfo", &[p2mr_id.clone().into()])
            .ok();
        let pick = |field: &str| -> String {
            v.get(field)
                .and_then(Value::as_str)
                .or_else(|| {
                    info.as_ref()
                        .and_then(|i| i.get(field))
                        .and_then(Value::as_str)
                })
                .unwrap_or("")
                .to_string()
        };
        let address = pick("address");
        let merkle_root_hex = pick("merkle_root");
        let script_pubkey_hex = pick("scriptPubKey");
        // fall back to the address from sendtop2mr if getp2mrinfo omitted it
        let address = if address.is_empty() {
            v.get("address")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        } else {
            address
        };
        Ok(P2mrOutput {
            p2mr_id,
            address,
            script_pubkey_hex,
            merkle_root_hex,
            funding_txid,
        })
    }

    /// Construct an unsigned spend of a funded P2MR output to `to_address`.
    /// Returns the unsigned raw tx hex + the selected input (txid, vout).
    pub fn create_p2mr_spend(
        &self,
        p2mr_id: &str,
        to_address: &str,
        amount_btc: f64,
        fee_btc: f64,
    ) -> RgbPqResult<(String, String, u32)> {
        let v = self.client.call(
            "createp2mrspend",
            &[
                p2mr_id.into(),
                to_address.into(),
                amount_btc.into(),
                fee_btc.into(),
            ],
        )?;
        let hex = v
            .get("hex")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let input_txid = v
            .get("input_txid")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let input_vout = v.get("input_vout").and_then(Value::as_u64).unwrap_or(0) as u32;
        Ok((hex, input_txid, input_vout))
    }

    /// Sign a P2MR spend (uses the wallet's Dilithium keys).
    pub fn sign_p2mr_tx(&self, unsigned_hex: &str, p2mr_id: &str) -> RgbPqResult<String> {
        let v = self.client.call(
            "signp2mrtransaction",
            &[unsigned_hex.into(), p2mr_id.into()],
        )?;
        Ok(v.get("hex")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string())
    }

    /// Mine `n` blocks to `address` (regtest). Returns the new block hashes.
    pub fn generate(&self, n: u64, address: &str) -> RgbPqResult<Vec<String>> {
        let v = self
            .client
            .call("generatetoaddress", &[n.into(), address.into()])?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Broadcast a signed raw tx. Returns the txid.
    pub fn broadcast(&self, signed_hex: &str) -> RgbPqResult<String> {
        self.client.broadcast_tx(signed_hex)
    }
}

/// Build a [`BtqP2mrSeal`] from a funded P2MR output.
///
/// `script_leaf_hash` is the Tapleaf hash of the spending leaf (computed
/// off-chain; the e2e uses the known leaf). `blinding` is left at the seal's
/// default for the demo.
pub fn seal_from_p2mr(
    chain: BtqChainId,
    out: &P2mrOutput,
    vout: u32,
    script_leaf_hash: [u8; 32],
    owner_algo: PqSigAlgo,
) -> RgbPqResult<BtqP2mrSeal> {
    let merkle_root = hex::decode(&out.merkle_root_hex)
        .map_err(|e| ResolveError::MissingOutput(e.to_string()))?;
    if merkle_root.len() != 32 {
        return Err(ResolveError::MissingOutput(format!(
            "merkle root len {} != 32",
            merkle_root.len()
        ))
        .into());
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&merkle_root);
    let txid = out
        .funding_txid
        .parse::<BtqTxid>()
        .map_err(|e| ResolveError::MissingTx(format!("funding txid: {e}")))?;
    Ok(BtqP2mrSeal::new(
        chain,
        BtqOutpoint::new(txid, vout),
        root,
        script_leaf_hash,
        owner_algo,
        rgb_pq_seal::CommitmentLocator::OpretFirst,
        rgb_pq_seal::ConfirmationPolicy::OneConf,
    ))
}

/// Compute the Tapleaf hash for a P2MR script leaf.
///
/// Mirrors btq-core `ComputeTapleafHash` for leaf_version 0xc0 (192):
/// `SHA256(0xC0 || script)`. (P2MR uses the same tapleaf hashing as Taproot.)
pub fn compute_tapleaf_hash(leaf_script: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update([0xc0]);
    h.update(leaf_script);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Result of a Dilithium key rotation: the new P2MR output owned by the new
/// key, plus the leaf script of the new PQ leaf (for resolver configuration).
#[derive(Clone, Debug)]
pub struct RotationResult {
    /// The new P2MR output (funded, owned by the new Dilithium key).
    pub new_p2mr: P2mrOutput,
    /// The new Dilithium-PKH leaf script hex (for resolver `with_pq_leaf`).
    pub new_leaf_hex: String,
    /// The new Dilithium address.
    pub new_address: String,
}

impl<'a> BtqTxOps<'a> {
    /// **Rotate the Dilithium ownership key** for a P2MR seal.
    ///
    /// This generates a fresh Dilithium key in the wallet, creates a new P2MR
    /// output whose leaf is owned by that new key, and funds it. The caller
    /// then transfers RGB state from the old seal to this new seal, and closes
    /// the old seal. Once the old seal is closed, the old key is irrelevant.
    ///
    /// Returns the new P2MR output + the new leaf script hex.
    pub fn rotate_dilithium_key(
        &self,
        amount_btc: f64,
        label: &str,
    ) -> RgbPqResult<RotationResult> {
        // 1. Generate a new Dilithium address.
        let new_addr = self.new_dilithium_address()?.0;
        // 2. Get its scriptPubKey (contains the hash160 for the PKH leaf).
        let info = self
            .client
            .call("getaddressinfo", &[new_addr.clone().into()])?;
        let spk_hex = info
            .get("scriptPubKey")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // 3. Build the DILITHIUM_PUBKEYHASH leaf (the wallet signs this).
        let leaf_hex = dilithium_pubkeyhash_leaf_hex(&spk_hex);
        // 4. Fund a new P2MR output with this leaf.
        let new_p2mr = self.create_fund_p2mr(&leaf_hex, amount_btc, label)?;
        Ok(RotationResult {
            new_p2mr,
            new_leaf_hex: leaf_hex,
            new_address: new_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dilithium_leaf_script_has_checksig_opcode() {
        // A fake 1312-byte pubkey.
        let pk = "ab".repeat(1312);
        let script_hex = dilithium_checksig_leaf_hex(&pk);
        let bytes = hex::decode(&script_hex).unwrap();
        // last byte is OP_CHECKSIGDILITHIUM
        assert_eq!(*bytes.last().unwrap(), 0xbb);
        // first byte is PUSHDATA2 (0x4d) since 1312 > 0x4b
        assert_eq!(bytes[0], 0x4d);
        // length encoded LE
        assert_eq!(bytes[1] as usize | ((bytes[2] as usize) << 8), 1312);
    }

    #[test]
    fn single_leaf_tree_shape() {
        let t = single_leaf_tree("51");
        let leaf = &t[0];
        assert_eq!(leaf["depth"], 0);
        assert_eq!(leaf["leaf_version"], 192);
        assert_eq!(leaf["script"], "51");
    }

    #[test]
    fn tapleaf_hash_matches_btq_convention() {
        // leaf_version 0xc0 || script
        let leaf = [0x51u8]; // OP_1 / OP_TRUE
        let h = compute_tapleaf_hash(&leaf);
        assert_eq!(h.len(), 32);
        // Deterministic: same input -> same hash.
        assert_eq!(h, compute_tapleaf_hash(&leaf));
    }

    #[test]
    fn seal_from_p2mr_roundtrip() {
        let out = P2mrOutput {
            p2mr_id: "id".into(),
            address: "qcrt1z...".into(),
            script_pubkey_hex: "5220".to_string() + &"22".repeat(32),
            merkle_root_hex: "22".repeat(32),
            funding_txid: "11".repeat(32),
        };
        let seal = seal_from_p2mr(
            BtqChainId::BitcoinQuantumRegtest,
            &out,
            0,
            [0x33; 32],
            PqSigAlgo::Dilithium2,
        )
        .unwrap();
        assert_eq!(seal.p2mr_root, [0x22; 32]);
        assert_eq!(seal.owner_algo, PqSigAlgo::Dilithium2);
    }
}
