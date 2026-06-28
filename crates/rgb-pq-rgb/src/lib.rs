//! RGB-PQ real RGB integration glue (Component 8).
//!
//! Uses the **real** RGB v0.11.1 production-track stack (vendored `rgbcore` +
//! `rgbstd` + `schemata`) to:
//!   * load the official NIA (Non-Inflatable Asset) schema kit;
//!   * issue a real NIA asset whose beneficiary owner-seal is a BTQ P2MR seal;
//!   * validate a consignment against an arbitrary `ResolveWitness` (which, in
//!     RGB-PQ, is the BTQ-backed [`BtqWitnessResolver`]).
//!
//! Nothing here is mocked: this exercises the actual RGB consensus issuance
//! and validation code paths. See `ARCHITECTURE.md` §3.4 and the NIA example
//! (`external/rgb-schemas/examples/nia.rs`).

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

use std::path::Path;

use bitcoin::Txid;
use rgb_pq_core::RgbPqResult;
use rgb_pq_seal::BtqP2mrSeal;
use rgbcore::validation::{ResolveWitness, ValidationConfig};
use rgbcore::{ChainNet, GenesisSeal, Identity};
use rgbstd::containers::{Consignment, ConsignmentExt, FileContent, Kit, ValidConsignment};
use rgbstd::contract::IssuerWrapper;
use rgbstd::invoice::Precision;
use rgbstd::persistence::Stock;
use rgbstd::stl::{AssetSpec, ContractTerms, RicardianContract};
use schemata::NonInflatableAsset;

pub use rgbcore::validation::WitnessStatus;
pub use rgbcore::ContractId;
pub use rgbstd::containers::ValidKit;

/// Specification of a demo asset to issue.
///
/// `ticker` and `name` are `&'static str` because RGB's `AssetSpec::new`
/// requires compile-time-static type names. For runtime-provided names, leak
/// them with `Box::leak` (acceptable for a fixed, small set of demo assets).
#[derive(Clone, Debug)]
pub struct DemoAssetSpec {
    /// Ticker, e.g. `"TEST"`.
    pub ticker: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Decimal precision.
    pub precision: Precision,
    /// Total issued supply (smallest units).
    pub supply: u64,
}

impl DemoAssetSpec {
    /// A sensible default demo asset.
    pub fn demo() -> Self {
        Self {
            ticker: "RGBPQ",
            name: "RGB-PQ demo asset",
            precision: Precision::CentiMicro,
            supply: 100_000,
        }
    }

    /// Construct from runtime strings by leaking them (demo-only).
    pub fn from_strings(ticker: String, name: String, precision: Precision, supply: u64) -> Self {
        Self {
            ticker: Box::leak(ticker.into_boxed_str()),
            name: Box::leak(name.into_boxed_str()),
            precision,
            supply,
        }
    }
}

/// An issued demo contract: the validated consignment + its id.
pub struct IssuedAsset {
    /// The validated contract consignment.
    pub contract: ValidConsignment<false>,
    /// The contract id (= genesis id).
    pub contract_id: ContractId,
}

/// A trivial resolver suitable for **genesis** issuance + import.
///
/// A genesis carries no witness transactions, so this resolver is never asked
/// to resolve one in practice; if it is, it reports the witness as unresolved
/// (the safe answer). For transfer/transition validation, callers must pass a
/// real `ResolveWitness` (the BTQ-backed resolver). This struct replaces the
/// upstream `DumbResolver`, which is `pub(crate)` and therefore unusable
/// directly.
pub struct GenesisResolver;

impl ResolveWitness for GenesisResolver {
    fn resolve_witness(
        &self,
        _txid: Txid,
    ) -> Result<WitnessStatus, rgbcore::validation::WitnessResolverError> {
        // Genesis has no witnesses; report unresolved rather than fabricate one.
        Ok(WitnessStatus::Unresolved)
    }
    fn check_chain_net(
        &self,
        _net: ChainNet,
    ) -> Result<(), rgbcore::validation::WitnessResolverError> {
        Ok(())
    }
}

/// Load and validate the official NIA kit from `nia_kit_path`.
///
/// `nia_kit_path` is normally `external/rgb-schemas/schemata/NonInflatableAsset.rgb`.
pub fn load_nia_kit(nia_kit_path: &Path) -> RgbPqResult<ValidKit> {
    let kit = Kit::load_file(nia_kit_path)
        .map_err(|e| rgb_pq_core::RgbPqError::RgbValidation(format!("load NIA kit: {e}")))?;
    // KitValidationError is an empty (infallible) enum; validation cannot fail,
    // but we route it through Debug for completeness.
    let valid = kit.validate().map_err(|e| {
        rgb_pq_core::RgbPqError::RgbValidation(format!("validate NIA kit: {e:?}"))
    })?;
    Ok(valid)
}

/// Issue a real NIA asset to a BTQ P2MR beneficiary seal.
///
/// `beneficiary_txid` is the txid of the funding transaction whose output is
/// the P2MR seal; `beneficiary_vout` is that output's index. The resulting
/// contract assigns the full supply to that seal.
pub fn issue_nia_to_btq_seal(
    nia_kit_path: &Path,
    chain_net: ChainNet,
    spec: DemoAssetSpec,
    beneficiary_txid: Txid,
    beneficiary_vout: u32,
) -> RgbPqResult<IssuedAsset> {
    // Fresh in-memory stock.
    let mut stock = Stock::in_memory();

    // Import the validated NIA kit.
    let kit = load_nia_kit(nia_kit_path)?;
    stock
        .import_kit(kit)
        .map_err(|e| rgb_pq_core::RgbPqError::RgbValidation(format!("import kit: {e}")))?;

    // Build the genesis, assigning fungible state to the BTQ beneficiary seal.
    let asset_spec = AssetSpec::new(spec.ticker, spec.name, spec.precision);
    let terms = ContractTerms {
        text: RicardianContract::default(),
        media: None,
    };
    let issued = stock
        .contract_builder(
            Identity::default(),
            NonInflatableAsset::schema().schema_id(),
            chain_net,
        )
        .map_err(stock_err)?
        .add_global_state("spec", asset_spec)
        .map_err(builder_err)?
        .add_global_state("terms", terms)
        .map_err(builder_err)?
        .add_global_state("issuedSupply", rgbstd::Amount::from(spec.supply))
        .map_err(builder_err)?
        .add_fungible_state(
            "assetOwner",
            GenesisSeal::new_random(beneficiary_txid, beneficiary_vout),
            spec.supply,
        )
        .map_err(builder_err)?
        .issue_contract()
        .map_err(builder_err)?;

    let contract_id = issued.contract_id();
    Ok(IssuedAsset {
        contract: issued,
        contract_id,
    })
}

/// Validate a consignment against a `ResolveWitness` (the BTQ-backed resolver
/// in production). Returns the validated consignment or a typed error.
pub fn validate_consignment<R: ResolveWitness>(
    consignment: Consignment<false>,
    resolver: &R,
    validation_config: ValidationConfig,
) -> RgbPqResult<ValidConsignment<false>> {
    consignment
        .validate(resolver, &validation_config)
        .map_err(|e| rgb_pq_core::RgbPqError::RgbValidation(format!("consignment invalid: {e}")))
}

fn stock_err<E: std::fmt::Display>(e: E) -> rgb_pq_core::RgbPqError {
    rgb_pq_core::RgbPqError::RgbValidation(format!("stock: {e}"))
}

fn builder_err<E: std::fmt::Display>(e: E) -> rgb_pq_core::RgbPqError {
    rgb_pq_core::RgbPqError::RgbValidation(format!("builder: {e}"))
}

/// Convenience: derive the RGB `ChainNet` stand-in for a BTQ seal's chain.
pub fn chain_net_for(seal: &BtqP2mrSeal) -> ChainNet {
    rgb_pq_resolver::ChainNetMapping::chain_net(seal.chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rgb_pq_seal::{BtqChainId};

    /// Locate the vendored NIA kit. In CI/tests the external repos are cloned
    /// by `scripts/setup-external.sh`.
    fn nia_kit() -> std::path::PathBuf {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../external/rgb-schemas/schemata/NonInflatableAsset.rgb");
        if !p.exists() {
            eprintln!(
                "note: NIA kit not found at {}; run scripts/setup-external.sh",
                p.display()
            );
        }
        p
    }

    fn dummy_txid() -> Txid {
        "14295d5bb1a191cdb6286dc0944df938421e3dfcbf0811353ccac4100c2068c5"
            .parse()
            .unwrap()
    }

    #[test]
    fn issue_real_nia_to_btq_seal() {
        let kit = nia_kit();
        if !kit.exists() {
            eprintln!("skipping: NIA kit absent (external not fetched)");
            return;
        }
        let issued = issue_nia_to_btq_seal(
            &kit,
            chain_net_for(&rgb_pq_seal::BtqP2mrSeal::new(
                BtqChainId::BitcoinQuantumRegtest,
                rgb_pq_seal::BtqOutpoint::new(rgb_pq_seal::BtqTxid::from_bytes([0x11; 32]), 0),
                [0x22; 32],
                [0x33; 32],
                rgb_pq_seal::PqSigAlgo::Dilithium2,
                rgb_pq_seal::CommitmentLocator::OpretFirst,
                rgb_pq_seal::ConfirmationPolicy::OneConf,
            )),
            DemoAssetSpec::demo(),
            dummy_txid(),
            0,
        )
        .expect("issuance must succeed");
        // A contract id is a non-zero 32-byte value.
        let id_bytes = issued.contract_id.to_byte_array();
        assert_ne!(id_bytes, [0u8; 32]);
        eprintln!("issued contract id: {}", issued.contract_id);
    }
}
