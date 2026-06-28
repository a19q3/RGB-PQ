# Cloned / forked repositories

RGB-PQ vendors four upstream repositories under `external/` (fetched by
`scripts/setup-external.sh`, gitignored). They are **path dependencies** so the
workspace is self-contained and reproducible.

## rgb-protocol (RGB production track, v0.11.1-rc.10)

| Repo | Crate | Lib name | Role |
|---|---|---|---|
| `rgb-protocol/rgb-consensus` | `rgb-consensus` | `rgbcore` | RGB consensus core: seals, transitions, anchors, MPC, validator, `ResolveWitness` |
| `rgb-protocol/rgb-ops` | `rgb-ops` | `rgbstd` | RGB stdlib: `Stock`, `ContractBuilder`, consignments, indexers (esplora/electrum) |
| `rgb-protocol/rgb-schemas` | `rgb-schemas` | `schemata` | Official RGB schemata (NIA, etc.) + issuance examples |

Authors: `Zoe Faltibà <zoefaltiba@gmail.com>` — the **actively maintained**
production track. We deliberately do **not** use the old Orlovsky / RGB-WG
v0.12 line.

## btq-ag/btq-core (BTQ node, 0.3.2)

A **Bitcoin Core fork** (C/C++ autotools). Built externally; RGB-PQ talks to it
over JSON-RPC. Provides:

- SegWit v2 / P2MR outputs (32-byte Merkle-root witness program, no key path);
- `bc1z`/`qcrt1z` bech32m addresses (HRP `qcrt` for regtest, `tbtq` testnet);
- `OP_CHECKSIGDILITHIUM` (0xbb) opcodes enabled under `P2MR_TAPSCRIPT`;
- P2MR wallet RPCs (`getnewp2mraddress`, `sendtop2mr`, `createp2mrspend`,
  `signp2mrtransaction`, …);
- inherited Bitcoin Core RPCs (`getrawtransaction`, `gettxoutproof`, …).

## Why rgb-protocol over RGB-WG v0.12

- v0.11.1-rc.x is the actively maintained track (last pushes 2026-04..06).
- Its `ResolveWitness` trait is the clean chain-backend seam RGB-PQ integrates
  against; the v0.12 line has a different, less stable API surface.
- Path-deps + `[patch.crates-io]` keep the whole graph on the vendored versions.

## Reusable tooling found

- `rgb-ops/src/indexers/esplora_blocking.rs` — reference `ResolveWitness` impl
  (the template for `BtqWitnessResolver`).
- `rgb-consensus/src/dbc/opret` — real `EmbedCommitVerify` for OP_RETURN
  commitments (used by the commitment binder).
- `rgb-schemas/examples/nia.rs` — real NIA issuance example (template for
  `issue_nia_to_btq_seal`).
- `btq-core/run_p2mr_rpc_e2e.sh` — canonical P2MR-over-RPC lifecycle (template
  for the e2e and tx helpers).
