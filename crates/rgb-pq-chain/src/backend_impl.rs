//! `BtqChainBackend` implementation for [`BtqRpcClient`].

use rgb_pq_core::{ResolveError, RgbPqResult};
use rgb_pq_seal::{BtqChainId, BtqOutpoint};

use crate::backend::{BtqChainBackend, BtqInclusionProof, BtqTx, BtqTxOut, ChainTip, TxStatus};
use crate::rpc::BtqRpcClient;

impl BtqChainBackend for BtqRpcClient {
    fn network_id(&self) -> BtqChainId {
        self.chain()
    }

    fn current_tip(&self) -> RgbPqResult<ChainTip> {
        self.get_tip()
    }

    fn get_tx(&self, txid: &str) -> RgbPqResult<Option<BtqTx>> {
        self.get_raw_tx(txid)
    }

    fn get_tx_status(&self, txid: &str) -> RgbPqResult<TxStatus> {
        BtqRpcClient::get_tx_status(self, txid)
    }

    fn get_output(&self, outpoint: &BtqOutpoint) -> RgbPqResult<Option<BtqTxOut>> {
        let vout = outpoint.vout;
        // gettxout returns null if spent or missing.
        let res = self.call(
            "gettxout",
            &[
                serde_json::Value::String(outpoint.txid.to_string()),
                (vout as i64).into(),
                false.into(),
            ],
        )?;
        if res.is_null() {
            // Distinguish "spent" from "missing": fetch the tx; if it doesn't
            // exist, it's missing; if it exists, the output is spent.
            let txid_s = outpoint.txid.to_string();
            if self.get_raw_tx(&txid_s)?.is_some() {
                // exists but gettxout null -> spent
                return Ok(Some(BtqTxOut {
                    outpoint: *outpoint,
                    value: 0,
                    script_pubkey: vec![],
                    spent: true,
                }));
            }
            return Ok(None);
        }
        let value = res
            .get("value")
            .and_then(|v| v.as_f64())
            .map(|btc| (btc * 1e8) as u64)
            .unwrap_or(0);
        let spk_hex = res
            .get("scriptPubKey")
            .and_then(|v| v.get("hex"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let spk = hex::decode(spk_hex).unwrap_or_default();
        Ok(Some(BtqTxOut {
            outpoint: *outpoint,
            value,
            script_pubkey: spk,
            spent: false,
        }))
    }

    fn get_spending_tx(&self, _outpoint: &BtqOutpoint) -> RgbPqResult<Option<BtqTx>> {
        // btq-core (Bitcoin Core fork) does not expose a direct
        // "getspendingtx" RPC. We approximate: scan the tx's own inputs is not
        // possible without an indexer. For the local e2e path the indexer
        // (Component 5) tracks this; the RPC backend surfaces
        // UnsupportedFeature so callers use the indexer instead.
        Err(
            ResolveError::Feature(rgb_pq_core::BtqFeature::RpcMethodUnsupported(
                "get_spending_tx (use the indexer)".into(),
            ))
            .into(),
        )
    }

    fn prove_tx_inclusion(&self, txid: &str) -> RgbPqResult<BtqInclusionProof> {
        self.get_inclusion_proof(txid)
    }

    fn confirmation_depth(&self, txid: &str) -> RgbPqResult<Option<u32>> {
        match self.get_tx_status(txid)? {
            TxStatus::Confirmed { confirmations, .. } => Ok(Some(confirmations)),
            TxStatus::Unconfirmed => Ok(None),
        }
    }

    fn broadcast_tx(&self, raw_hex: &str) -> RgbPqResult<String> {
        self.send_raw_tx(raw_hex)
    }
}
