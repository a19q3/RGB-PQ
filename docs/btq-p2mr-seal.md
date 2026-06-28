# BTQ P2MR seal encoding

The canonical BTQ P2MR seal is [`rgb_pq_seal::BtqP2mrSeal`]. It carries every
field the resolver needs to verify a seal on chain:

| Field | Type | Role |
|---|---|---|
| `version` | `SealVersion` | Encoding version (`V0`) |
| `chain_id` | `BtqChainId` | regtest/testnet only (mainnet rejected) |
| `outpoint` | `BtqOutpoint` | txid + vout that will be spent to close the seal |
| `p2mr_root` | `[u8;32]` | the SegWit v2 witness program (Merkle root) |
| `script_leaf_hash` | `[u8;32]` | Tapleaf hash of the spending Dilithium leaf |
| `owner_algo` | `PqSigAlgo` | Dilithium2/5 (secp256k1 not representable) |
| `commitment_locator` | `CommitmentLocator` | which OP_RETURN output holds the RGB commitment |
| `confirmation_policy` | `ConfirmationPolicy` | required finality depth |

## Binary encoding

```
MAGIC("RGBPQSEAL") || version(1) || DOMAIN_TAG("rgbpq:v0") || ver(1) || body
```

where `body` is:

```
chain(1) || txid(32) || vout(4 LE) || p2mr_root(32) || script_leaf_hash(32)
        || owner_algo(1) || locator(len-prefixed) || policy(len-prefixed)
```

## Textual encoding

bech32m with HRP `rgbpqseal`, carrying the body bytes.

## Canonical digest

`SHA256( "rgbpq:v0" || ver || chain || 0x00 || "p2mr" || 0x00 || ver || body )`.

Changing **any** field changes the digest (property-tested). This is the
domain-separation guarantee that prevents cross-chain / cross-seal confusion.

## Test vectors

See `crates/rgb-pq-seal/src/vectors.rs` for pinned known-answer vectors.
