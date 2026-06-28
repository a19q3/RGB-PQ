//! Domain separation for RGB-PQ.
//!
//! Every canonical seal encoding and every commitment digest produced anywhere
//! in the workspace is prefixed with the constant domain tag below. This is
//! the single source of truth; do not inline these bytes elsewhere.
//!
//! The tag binds together:
//!   * the RGB-PQ protocol name and version (`rgbpq:v0`);
//!   * the chain id (Bitcoin Quantum regtest / testnet only — never mainnet);
//!   * the seal type (`p2mr`);
//!   * the remaining seal fields (txid, vout, p2mr_root, script_leaf_hash,
//!     owner_algo, commitment_locator, confirmation_policy).
//!
//! It exists to make cross-chain / cross-seal confusion unrepresentable:
//! Bitcoin mainnet/testnet/signet/regtest, ordinary Taproot/P2TR, ordinary RGB
//! Bitcoin seals, non-P2MR BTQ outputs and secp256k1 ownership paths all hash
//! differently and are therefore rejected at the boundary.

/// Domain-separation version. Bumped only on an incompatible encoding change.
pub const DOMAIN_SEPARATION_VERSION: u8 = 0;

/// ASCII domain tag embedded at the start of every domain-separated digest.
pub const DOMAIN_TAG: &[u8] = b"rgbpq:v0";

/// A structured domain-separation separator: the bytes that prefix every
/// canonical digest. It is the literal `DOMAIN_TAG` followed by the version
/// byte, then the chain and seal-type fields supplied by the caller.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Domain<'a> {
    /// `bitcoin-quantum-regtest` or `bitcoin-quantum-testnet` (never mainnet).
    pub chain: &'a str,
    /// Always `p2mr` for this protocol.
    pub seal_type: &'a str,
}

impl<'a> Domain<'a> {
    /// The canonical P2MR domain separator.
    pub const P2MR_SEAL_TYPE: &'static str = "p2mr";

    /// Construct the canonical P2MR domain for a chain name.
    pub fn p2mr(chain: &'a str) -> Self {
        Self {
            chain,
            seal_type: Self::P2MR_SEAL_TYPE,
        }
    }

    /// Write the fixed domain prefix into `buf`. Returns the number of bytes
    /// written. The prefix is: `DOMAIN_TAG || DOMAIN_SEPARATION_VERSION ||
    /// chain || 0x00 || seal_type || 0x00`.
    pub fn write_prefix(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(DOMAIN_TAG);
        buf.push(DOMAIN_SEPARATION_VERSION);
        buf.extend_from_slice(self.chain.as_bytes());
        buf.push(0); // NUL separator
        buf.extend_from_slice(self.seal_type.as_bytes());
        buf.push(0); // NUL separator
    }

    /// Convenience: produce a fresh `Vec<u8>` seeded with the prefix.
    pub fn prefixed(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        self.write_prefix(&mut v);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tag_is_stable() {
        assert_eq!(DOMAIN_TAG, b"rgbpq:v0");
        assert_eq!(DOMAIN_SEPARATION_VERSION, 0);
    }

    #[test]
    fn p2mr_prefix_is_deterministic() {
        let d = Domain::p2mr("bitcoin-quantum-regtest");
        let p = d.prefixed();
        // tag || ver || chain || NUL || seal_type || NUL
        let expected: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(b"rgbpq:v0");
            v.push(0u8);
            v.extend_from_slice(b"bitcoin-quantum-regtest");
            v.push(0);
            v.extend_from_slice(b"p2mr");
            v.push(0);
            v
        };
        assert_eq!(p, expected);
    }

    #[test]
    fn different_chains_produce_different_prefixes() {
        let a = Domain::p2mr("bitcoin-quantum-regtest").prefixed();
        let b = Domain::p2mr("bitcoin-quantum-testnet").prefixed();
        assert_ne!(a, b);
    }

    #[test]
    fn p2mr_seal_type_constant() {
        assert_eq!(Domain::P2MR_SEAL_TYPE, "p2mr");
    }
}
