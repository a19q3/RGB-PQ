//! BTQ JSON-RPC client (Component 4).
//!
//! Talks to a `btqd` node over HTTP JSON-RPC. Implements:
//!   * local regtest / testnet configuration;
//!   * RPC URL + cookie/basic-auth credentials;
//!   * timeout handling;
//!   * typed errors (never panics on RPC errors);
//!   * a bounded retry policy for transient transport errors;
//!   * network verification (the node must report the expected chain);
//!   * raw transaction fetch / broadcast / block fetch / inclusion proof fetch.
//!
//! It never logs secrets. Errors carry the endpoint URL *without* credentials.

use std::time::Duration;

use serde_json::Value;

use rgb_pq_core::{ChainConfusion, NodeUnavailable, ResolveError, RgbPqResult, RpcError};
use rgb_pq_seal::BtqChainId;

use crate::backend::{node_unavailable, BtqInclusionProof, BtqTx, ChainTip, TxStatus};
use crate::network::BtqRpcConfig;

/// Default per-request timeout.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Default retry count for transient transport errors.
pub const DEFAULT_RETRIES: u32 = 2;

/// A BTQ JSON-RPC client.
pub struct BtqRpcClient {
    config: BtqRpcConfig,
    timeout: Duration,
    retries: u32,
    agent: ureq::Agent,
}

impl BtqRpcClient {
    /// Construct a client from a configuration.
    pub fn new(config: BtqRpcConfig) -> Self {
        let timeout = Duration::from_secs(config.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS));
        let retries = config.retries.unwrap_or(DEFAULT_RETRIES);
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        Self {
            config,
            timeout,
            retries,
            agent,
        }
    }

    /// The chain this client is configured for.
    pub fn chain(&self) -> BtqChainId {
        self.config.chain
    }

    /// The endpoint URL *without* credentials (safe to embed in errors/logs).
    fn safe_endpoint(&self) -> String {
        // Strip userinfo if present.
        let url = &self.config.url;
        if let Some(after_scheme) = url.split("://").nth(1) {
            let host = after_scheme.split('@').next_back().unwrap_or(after_scheme);
            format!("{}://{host}", url.split("://").next().unwrap_or("http"))
        } else {
            url.clone()
        }
    }

    /// The URL to POST to: the base URL plus an optional `/wallet/<name>`
    /// suffix when a wallet is configured (Bitcoin Core wallet-scoped RPC).
    fn request_url(&self) -> String {
        match &self.config.wallet {
            Some(w) => format!("{}/wallet/{}", self.config.url, w),
            None => self.config.url.clone(),
        }
    }

    /// Set (or clear) the wallet context for subsequent calls. When set,
    /// wallet-scoped RPCs route through `<url>/wallet/<name>`.
    pub fn set_wallet(&mut self, wallet: Option<&str>) {
        self.config.wallet = wallet.map(|w| w.to_string());
    }

    /// Verify the node is on the expected chain by inspecting
    /// `getblockchaininfo`.
    pub fn verify_network(&self) -> RgbPqResult<()> {
        let info = self.call("getblockchaininfo", &[])?;
        let chain = info
            .get("chain")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let expected = crate::network::btq_chain_name(self.config.chain);
        if chain != expected {
            return Err(ChainConfusion::WrongNetwork {
                expected: expected.to_string(),
                actual: chain.to_string(),
            }
            .into());
        }
        Ok(())
    }

    /// Perform a JSON-RPC call with retry on transient transport errors.
    pub fn call(&self, method: &str, params: &[Value]) -> RgbPqResult<Value> {
        let endpoint_safe = self.safe_endpoint();
        let request_url = self.request_url();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut last_err: Option<RpcError> = None;
        for attempt in 0..=self.retries {
            let req = self
                .agent
                .post(&request_url)
                .set("Content-Type", "application/json");
            let req = match &self.config.auth {
                crate::network::BtqAuth::UserPass { user, pass } => {
                    req.set("Authorization", &basic_auth(user, pass))
                }
                crate::network::BtqAuth::None => req,
            };
            match req.send_string(body.to_string().as_str()) {
                Ok(resp) => {
                    let body = resp.into_string().unwrap_or_default();
                    return parse_response(&body, &endpoint_safe);
                }
                Err(ureq::Error::Status(code, resp)) => {
                    // HTTP error — do not retry (server answered).
                    let detail = resp.into_string().unwrap_or_default();
                    return Err(RpcError::HttpStatus {
                        status: code,
                        endpoint: endpoint_safe,
                        detail,
                    }
                    .into());
                }
                Err(e) => {
                    // Transport error — retryable. ureq 2 surfaces timeouts as
                    // ErrorKind::Io (there is no Timeout variant); we keep the
                    // raw transport detail and never panic.
                    let detail = e.to_string();
                    let is_timeout = detail.contains("timed out") || detail.contains("timeout");
                    last_err = Some(if is_timeout {
                        RpcError::Timeout(self.timeout.as_secs(), endpoint_safe.clone())
                    } else {
                        RpcError::Transport {
                            endpoint: endpoint_safe.clone(),
                            detail,
                        }
                    });
                    if attempt < self.retries {
                        std::thread::sleep(Duration::from_millis(200 * (attempt as u64 + 1)));
                        continue;
                    }
                }
            }
        }
        let rpc_err = last_err.unwrap_or_else(|| RpcError::Transport {
            endpoint: endpoint_safe,
            detail: "unknown transport error".into(),
        });
        // If the error looks like the node is down, surface NodeUnavailable.
        if matches!(
            rpc_err,
            RpcError::Timeout(_, _) | RpcError::Transport { .. }
        ) {
            Err(ResolveError::NodeUnavailable(NodeUnavailable(rpc_err.to_string())).into())
        } else {
            Err(rpc_err.into())
        }
    }
}

fn parse_response(body: &str, endpoint: &str) -> RgbPqResult<Value> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| RpcError::Decode(endpoint.to_string(), e.to_string()))?;
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(-1);
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        return Err(RpcError::RpcLevel {
            code,
            endpoint: endpoint.to_string(),
            message: msg,
        }
        .into());
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| RpcError::Decode(endpoint.to_string(), "no result field".into()).into())
}

fn basic_auth(user: &str, pass: &str) -> String {
    use base64_encode::encode;
    let combined = format!("{user}:{pass}");
    format!("Basic {}", encode(combined.as_bytes()))
}

/// Minimal base64 encoder (avoids pulling a base64 crate just for auth).
mod base64_encode {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(TABLE[(n & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }
}

// =========================================================================
// High-level convenience methods used by the backend impl.
// =========================================================================

impl BtqRpcClient {
    /// `getblockchaininfo` -> [`ChainTip`].
    pub fn get_tip(&self) -> RgbPqResult<ChainTip> {
        let info = self.call("getblockchaininfo", &[])?;
        let height = info
            .get("headers")
            .and_then(Value::as_u64)
            .ok_or_else(|| node_unavailable("missing headers"))? as u32;
        let hash = info
            .get("bestblockhash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(ChainTip { height, hash })
    }

    /// `getrawtransaction` (verbose) -> [`BtqTx`].
    pub fn get_raw_tx(&self, txid: &str) -> RgbPqResult<Option<BtqTx>> {
        let res = self.call("getrawtransaction", &[txid.into(), true.into()]);
        match res {
            Ok(v) => {
                let hex = v
                    .get("hex")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let raw = hex::decode(&hex).unwrap_or_default();
                let status = tx_status_from_verbose(&v);
                Ok(Some(BtqTx {
                    txid: txid.to_string(),
                    raw,
                    status,
                }))
            }
            Err(rgb_pq_core::RgbPqError::Resolve(ResolveError::Rpc(RpcError::RpcLevel {
                code: -5,
                ..
            }))) => {
                // -5 = "No such mempool or blockchain transaction"
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// `gettxoutproof` -> [`BtqInclusionProof`].
    ///
    /// On nodes without `-txindex`, the tx must be in the mempool OR a
    /// `blockhash` must be supplied. We fetch the blockhash from
    /// `gettransaction` (wallet-scoped) when available and pass it to
    /// `gettxoutproof`.
    pub fn get_inclusion_proof(&self, txid: &str) -> RgbPqResult<BtqInclusionProof> {
        // Try to get the blockhash via the wallet (works for wallet-owned txs).
        let block_hash: Option<String> = self
            .call("gettransaction", &[txid.into(), true.into()])
            .ok()
            .and_then(|v| {
                v.get("blockhash")
                    .and_then(|b| b.as_str().map(String::from))
            });

        let params: Vec<Value> = match &block_hash {
            Some(bh) => vec![vec![txid.to_string()].into(), bh.clone().into()],
            None => vec![vec![txid.to_string()].into()],
        };
        let proof_v = self.call("gettxoutproof", &params)?;
        let proof = proof_v
            .as_str()
            .ok_or_else(|| node_unavailable("gettxoutproof returned non-string"))?
            .to_string();
        Ok(BtqInclusionProof {
            txid: txid.to_string(),
            block_hash: block_hash.unwrap_or_default(),
            proof_hex: proof,
        })
    }

    /// `getrawtransaction` verbose status only -> [`TxStatus`].
    pub fn get_tx_status(&self, txid: &str) -> RgbPqResult<TxStatus> {
        match self.get_raw_tx(txid)? {
            Some(tx) => Ok(tx.status),
            None => Err(ResolveError::MissingTx(txid.to_string()).into()),
        }
    }

    /// `sendrawtransaction` -> txid.
    pub fn send_raw_tx(&self, hex: &str) -> RgbPqResult<String> {
        Ok(self
            .call("sendrawtransaction", &[hex.into()])?
            .as_str()
            .ok_or_else(|| node_unavailable("sendrawtransaction returned non-string"))?
            .to_string())
    }
}

fn tx_status_from_verbose(v: &Value) -> TxStatus {
    let confirmations = v.get("confirmations").and_then(Value::as_u64).unwrap_or(0) as u32;
    if confirmations == 0 {
        return TxStatus::Unconfirmed;
    }
    let block_hash = v
        .get("blockhash")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let block_height = v.get("blockheight").and_then(Value::as_u64).unwrap_or(0) as u32;
    let time = v.get("blocktime").and_then(Value::as_i64).unwrap_or(0);
    TxStatus::Confirmed {
        height: block_height,
        block_hash,
        confirmations,
        time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::BtqAuth;

    fn cfg() -> BtqRpcConfig {
        BtqRpcConfig {
            chain: BtqChainId::BitcoinQuantumRegtest,
            url: "http://127.0.0.1:28543".into(),
            auth: BtqAuth::UserPass {
                user: "btq".into(),
                pass: "btqpass".into(),
            },
            timeout_secs: Some(1),
            retries: Some(0),
            wallet: None,
        }
    }

    #[test]
    fn safe_endpoint_strips_credentials() {
        let mut c = cfg();
        c.url = "http://btq:btqpass@127.0.0.1:28543".into();
        let client = BtqRpcClient::new(c);
        assert_eq!(client.safe_endpoint(), "http://127.0.0.1:28543");
    }

    #[test]
    fn node_unavailable_when_no_node() {
        // Use a port that is guaranteed to have no node (port 9 = discard),
        // so this test is independent of any locally-running btqd.
        let mut c = cfg();
        c.url = "http://127.0.0.1:9".into();
        c.retries = Some(0);
        let client = BtqRpcClient::new(c);
        let res = client.call("getblockchaininfo", &[]);
        let err = res.unwrap_err();
        assert!(
            matches!(
                err,
                rgb_pq_core::RgbPqError::Resolve(ResolveError::NodeUnavailable(_))
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_response_handles_rpc_error() {
        let body = r#"{"result":null,"error":{"code":-5,"message":"No such mempool or blockchain transaction"}}"#;
        let err = parse_response(body, "http://x").unwrap_err();
        assert!(matches!(
            err,
            rgb_pq_core::RgbPqError::Rpc(RpcError::RpcLevel { code: -5, .. })
        ));
    }

    #[test]
    fn parse_response_returns_result() {
        let body = r#"{"result":{"chain":"regtest"},"error":null}"#;
        let v = parse_response(body, "http://x").unwrap();
        assert_eq!(v.get("chain").and_then(Value::as_str), Some("regtest"));
    }

    #[test]
    fn base64_auth_header() {
        assert_eq!(basic_auth("btq", "btqpass"), "Basic YnRxOmJ0cXBhc3M=");
    }
}
