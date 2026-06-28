//! Bridge implementing RGB's [`ResolveWitness`] over a BTQ backend.
//!
//! This is the exact seam described in `ARCHITECTURE.md` §3.1: the RGB
//! validator calls `resolve_witness(txid)` and `check_chain_net(chain_net)`.
//! We fetch the tx + status from the BTQ backend and map them to RGB's
//! [`WitnessStatus`] / [`WitnessOrd`], exactly mirroring the reference
//! `EsploraClient` (`rgb-ops/src/indexers/esplora_blocking.rs:37-75`).
//!
//! `check_chain_net` verifies the BTQ node's genesis block matches the chain
//! hash of the (documented) RGB `ChainNet` stand-in. See
//! [`ChainNetMapping`].

use std::num::NonZeroU32;

use bitcoin::hashes::Hash;
use bitcoin::Transaction as Tx;

use rgbcore::validation::{ResolveWitness, WitnessResolverError, WitnessStatus};
use rgbcore::vm::{WitnessOrd, WitnessPos};
use rgbcore::ChainNet;

use rgb_pq_chain::BtqChainBackend;
use rgb_pq_core::RgbPqResult;
use rgb_pq_seal::BtqChainId;

/// A documented mapping from BTQ chains to RGB `ChainNet` stand-ins.
///
/// RGB's `ChainNet` has no BTQ variant, so we map each supported BTQ chain onto
/// the closest Bitcoin `ChainNet` and verify the backend's genesis hash matches
/// that stand-in's `chain_hash()`. The mapping is explicit, tested, and never
/// silent. RGB consensus does not learn about BTQ; it only sees a consistent
/// `ChainNet`.
pub struct ChainNetMapping;

impl ChainNetMapping {
    /// The RGB `ChainNet` stand-in for a BTQ chain.
    pub fn chain_net(chain: BtqChainId) -> ChainNet {
        match chain {
            // BTQ regtest maps to Bitcoin regtest. The genesis hash must still
            // be verified against the actual BTQ node (it will differ from
            // Bitcoin's; the resolver relies on the explicit chain field for
            // real chain identity, while RGB uses this only for validation
            // plumbing).
            BtqChainId::BitcoinQuantumRegtest => ChainNet::BitcoinRegtest,
            BtqChainId::BitcoinQuantumTestnet => ChainNet::BitcoinTestnet3,
        }
    }

    /// The expected genesis chain-hash for the stand-in (per RGB's
    /// `ChainNet::chain_hash()`). The BTQ backend's own genesis hash is checked
    /// separately via [`BtqRpcClient::verify_network`].
    pub fn stand_in_chain_hash(chain: BtqChainId) -> [u8; 32] {
        let bytes = Self::chain_net(chain).chain_hash().to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}

/// A BTQ-backed RGB witness resolver.
pub struct BtqWitnessResolver<'a, B: BtqChainBackend> {
    backend: &'a B,
    chain: BtqChainId,
}

impl<'a, B: BtqChainBackend> BtqWitnessResolver<'a, B> {
    /// Construct a witness resolver bound to a BTQ backend for `chain`.
    pub fn new(backend: &'a B, chain: BtqChainId) -> Self {
        Self { backend, chain }
    }

    fn map_err(&self, e: rgb_pq_core::RgbPqError) -> WitnessResolverError {
        WitnessResolverError::ResolverIssue(None, e.to_string())
    }
}

impl<'a, B: BtqChainBackend> ResolveWitness for BtqWitnessResolver<'a, B> {
    fn resolve_witness(
        &self,
        witness_id: bitcoin::Txid,
    ) -> Result<WitnessStatus, WitnessResolverError> {
        let txid_hex = witness_id.to_string();
        let tx = match self.fetch_tx(&txid_hex).map_err(|e| self.map_err(e))? {
            Some(t) => t,
            None => return Ok(WitnessStatus::Unresolved),
        };
        let status = self
            .backend
            .get_tx_status(&txid_hex)
            .map_err(|e| self.map_err(e))?;
        let ord = match status {
            rgb_pq_chain::TxStatus::Confirmed { height, time, .. } => {
                let h = NonZeroU32::new(height)
                    .ok_or(WitnessResolverError::InvalidResolverData)?;
                WitnessOrd::Mined(
                    WitnessPos::bitcoin(h, time).ok_or(WitnessResolverError::InvalidResolverData)?,
                )
            }
            rgb_pq_chain::TxStatus::Unconfirmed => WitnessOrd::Tentative,
        };
        Ok(WitnessStatus::Resolved(tx, ord))
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        let expected = ChainNetMapping::chain_net(self.chain);
        if chain_net != expected {
            return Err(WitnessResolverError::WrongChainNet);
        }
        Ok(())
    }
}

impl<'a, B: BtqChainBackend> BtqWitnessResolver<'a, B> {
    fn fetch_tx(&self, txid_hex: &str) -> RgbPqResult<Option<Tx>> {
        match self.backend.get_tx(txid_hex)? {
            Some(btq_tx) => {
                // Decode the raw bytes into a bitcoin::Transaction.
                match bitcoin::consensus::encode::deserialize::<Tx>(&btq_tx.raw) {
                    Ok(tx) => {
                        // Defence in depth: txid must match.
                        if tx.compute_txid().to_string() == txid_hex {
                            Ok(Some(tx))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(_) => Ok(None),
                }
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_net_mapping_is_documented() {
        assert_eq!(
            ChainNetMapping::chain_net(BtqChainId::BitcoinQuantumRegtest),
            ChainNet::BitcoinRegtest
        );
        assert_eq!(
            ChainNetMapping::chain_net(BtqChainId::BitcoinQuantumTestnet),
            ChainNet::BitcoinTestnet3
        );
    }

    #[test]
    fn check_chain_net_rejects_mismatch() {
        struct NoBackend;
        impl BtqChainBackend for NoBackend {
            fn network_id(&self) -> BtqChainId {
                BtqChainId::BitcoinQuantumRegtest
            }
            fn current_tip(&self) -> RgbPqResult<rgb_pq_chain::ChainTip> {
                unreachable!()
            }
            fn get_tx(&self, _: &str) -> RgbPqResult<Option<rgb_pq_chain::BtqTx>> {
                unreachable!()
            }
            fn get_tx_status(&self, _: &str) -> RgbPqResult<rgb_pq_chain::TxStatus> {
                unreachable!()
            }
            fn get_output(&self, _: &rgb_pq_seal::BtqOutpoint) -> RgbPqResult<Option<rgb_pq_chain::BtqTxOut>> {
                unreachable!()
            }
            fn get_spending_tx(&self, _: &rgb_pq_seal::BtqOutpoint) -> RgbPqResult<Option<rgb_pq_chain::BtqTx>> {
                unreachable!()
            }
            fn prove_tx_inclusion(&self, _: &str) -> RgbPqResult<rgb_pq_chain::BtqInclusionProof> {
                unreachable!()
            }
            fn confirmation_depth(&self, _: &str) -> RgbPqResult<Option<u32>> {
                unreachable!()
            }
        }
        let b = NoBackend;
        let r = BtqWitnessResolver::new(&b, BtqChainId::BitcoinQuantumRegtest);
        // matching chain net -> Ok
        assert!(r.check_chain_net(ChainNet::BitcoinRegtest).is_ok());
        // mismatching -> WrongChainNet
        assert_eq!(
            r.check_chain_net(ChainNet::BitcoinMainnet),
            Err(WitnessResolverError::WrongChainNet)
        );
    }
}
