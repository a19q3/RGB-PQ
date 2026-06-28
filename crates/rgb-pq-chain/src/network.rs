//! Network / connection configuration for the BTQ RPC client.

use rgb_pq_seal::BtqChainId;

/// RPC authentication.
#[derive(Clone, Debug)]
pub enum BtqAuth {
    /// No auth.
    None,
    /// Basic username/password auth (`-rpcuser` / `-rpcpassword`).
    UserPass {
        /// RPC username.
        user: String,
        /// RPC password.
        pass: String,
    },
}

/// RPC connection configuration.
#[derive(Clone, Debug)]
pub struct BtqRpcConfig {
    /// The BTQ chain this client targets (drives network verification).
    pub chain: BtqChainId,
    /// Full RPC URL including credentials if any, e.g.
    /// `http://btq:btqpass@127.0.0.1:28543`. Credentials are stripped from
    /// errors/logs.
    pub url: String,
    /// Auth.
    pub auth: BtqAuth,
    /// Per-request timeout in seconds.
    pub timeout_secs: Option<u64>,
    /// Transient-error retry count.
    pub retries: Option<u32>,
    /// Optional wallet name. When set, wallet-scoped RPCs are routed through
    /// `<url>/wallet/<name>` (Bitcoin Core convention).
    pub wallet: Option<String>,
}

impl BtqRpcConfig {
    /// A convenient constructor for a local regtest node (the e2e default).
    pub fn local_regtest(rpc_user: &str, rpc_pass: &str, port: u16) -> Self {
        Self {
            chain: BtqChainId::BitcoinQuantumRegtest,
            url: format!("http://127.0.0.1:{port}"),
            auth: BtqAuth::UserPass {
                user: rpc_user.to_string(),
                pass: rpc_pass.to_string(),
            },
            timeout_secs: None,
            retries: None,
            wallet: None,
        }
    }

    /// A convenient constructor for a local testnet node.
    pub fn local_testnet(rpc_user: &str, rpc_pass: &str, port: u16) -> Self {
        Self {
            chain: BtqChainId::BitcoinQuantumTestnet,
            url: format!("http://127.0.0.1:{port}"),
            auth: BtqAuth::UserPass {
                user: rpc_user.to_string(),
                pass: rpc_pass.to_string(),
            },
            timeout_secs: None,
            retries: None,
            wallet: None,
        }
    }
}

/// The chain name reported by `getblockchaininfo` for a chain.
///
/// `btq-core` reports `"regtest"` / `"test"` / `"main"` (Bitcoin Core
/// convention). We map only the BTQ chains we support.
pub(crate) fn btq_chain_name(chain: BtqChainId) -> &'static str {
    match chain {
        BtqChainId::BitcoinQuantumRegtest => "regtest",
        BtqChainId::BitcoinQuantumTestnet => "test",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_regtest_config() {
        let c = BtqRpcConfig::local_regtest("u", "p", 28543);
        assert_eq!(c.chain, BtqChainId::BitcoinQuantumRegtest);
        assert_eq!(c.url, "http://127.0.0.1:28543");
    }

    #[test]
    fn chain_names_match_btq_core() {
        assert_eq!(btq_chain_name(BtqChainId::BitcoinQuantumRegtest), "regtest");
        assert_eq!(btq_chain_name(BtqChainId::BitcoinQuantumTestnet), "test");
    }
}
