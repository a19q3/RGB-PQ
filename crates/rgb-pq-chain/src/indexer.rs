//! BTQ indexer (Component 5).
//!
//! Tracks watched outpoints, their outputs, spending transactions, confirmation
//! depth, block height/hash, and supports reorg rollback + rescan-from-height.
//!
//! Two implementations share the [`Indexer`] trait:
//!   * [`MemIndexer`] — deterministic, in-memory, local-only (clearly marked);
//!   * `SqliteIndexer` — persistent (behind the `sqlite` feature).
//!
//! The indexer is a *cache* over the chain backend. It does not make consensus
//! decisions; the resolver (Component 6) does the final verification.

use std::collections::BTreeMap;

use rgb_pq_core::RgbPqResult;
use rgb_pq_seal::BtqOutpoint;

#[cfg(test)]
use crate::backend::TxStatus;
use crate::backend::{BtqTx, BtqTxOut, ChainTip};

/// The set of facts an indexer records about a watched outpoint.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IndexedOutpoint {
    /// The output (when seen).
    pub output: Option<BtqTxOut>,
    /// The txid that spends this outpoint, if known.
    pub spending_txid: Option<String>,
    /// Confirmation depth of the spending tx (0 if unconfirmed or unknown).
    pub spending_confirmations: u32,
}

/// The indexer abstraction.
pub trait Indexer {
    /// The best-known chain tip the indexer has synced to.
    fn tip(&self) -> ChainTip;

    /// Watch an outpoint.
    fn watch(&mut self, outpoint: &BtqOutpoint) -> RgbPqResult<()>;

    /// Record (or update) the output for a watched outpoint.
    fn record_output(&mut self, outpoint: &BtqOutpoint, out: BtqTxOut) -> RgbPqResult<()>;

    /// Record (or update) the spending tx for a watched outpoint.
    fn record_spend(&mut self, outpoint: &BtqOutpoint, spending_tx: &BtqTx) -> RgbPqResult<()>;

    /// Update confirmation depth for a spending tx of a watched outpoint.
    fn update_confirmations(&mut self, outpoint: &BtqOutpoint, depth: u32) -> RgbPqResult<()>;

    /// Look up the indexed facts for a watched outpoint.
    fn get(&self, outpoint: &BtqOutpoint) -> Option<&IndexedOutpoint>;

    /// Roll the indexer back to a previous height (reorg handling). Drops any
    /// spend facts recorded at heights strictly greater than `to_height`.
    fn rollback(&mut self, to_height: u32) -> RgbPqResult<()>;

    /// Rescan from a height (clears confirmations for spending txs confirmed
    /// at or above `from_height`, marking them for re-confirmation).
    fn rescan_from(&mut self, from_height: u32) -> RgbPqResult<()>;

    /// Set the current tip.
    fn set_tip(&mut self, tip: ChainTip);
}

/// Internal stored entry (adds spend_height for rollback bookkeeping).
#[derive(Clone, Debug, Default)]
struct Entry {
    view: IndexedOutpoint,
    spend_height: Option<u32>,
}

// =========================================================================
// In-memory indexer (local-only, deterministic, tested).
// =========================================================================

/// A deterministic in-memory indexer.
///
/// **Local-only.** Suitable for tests and the local e2e harness. Marked as
/// such because it holds no durable state; use `SqliteIndexer` (sqlite feature)
/// for persistence.
#[derive(Default)]
pub struct MemIndexer {
    height: u32,
    tip_hash: String,
    entries: BTreeMap<String, Entry>,
}

fn key(o: &BtqOutpoint) -> String {
    format!("{}:{}", o.txid, o.vout)
}

impl MemIndexer {
    /// Construct an empty in-memory indexer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of watched outpoints.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the indexer watches nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Indexer for MemIndexer {
    fn tip(&self) -> ChainTip {
        ChainTip {
            height: self.height,
            hash: self.tip_hash.clone(),
        }
    }

    fn watch(&mut self, outpoint: &BtqOutpoint) -> RgbPqResult<()> {
        self.entries.entry(key(outpoint)).or_default();
        Ok(())
    }

    fn record_output(&mut self, outpoint: &BtqOutpoint, out: BtqTxOut) -> RgbPqResult<()> {
        let e = self.entries.entry(key(outpoint)).or_default();
        e.view.output = Some(out);
        Ok(())
    }

    fn record_spend(&mut self, outpoint: &BtqOutpoint, spending_tx: &BtqTx) -> RgbPqResult<()> {
        let e = self.entries.entry(key(outpoint)).or_default();
        e.view.spending_txid = Some(spending_tx.txid.clone());
        e.view.spending_confirmations = spending_tx.status.confirmations();
        e.spend_height = Some(self.height);
        Ok(())
    }

    fn update_confirmations(&mut self, outpoint: &BtqOutpoint, depth: u32) -> RgbPqResult<()> {
        let e = self.entries.entry(key(outpoint)).or_default();
        e.view.spending_confirmations = depth;
        Ok(())
    }

    fn get(&self, outpoint: &BtqOutpoint) -> Option<&IndexedOutpoint> {
        self.entries.get(&key(outpoint)).map(|e| &e.view)
    }

    fn rollback(&mut self, to_height: u32) -> RgbPqResult<()> {
        for e in self.entries.values_mut() {
            if matches!(e.spend_height, Some(h) if h > to_height) {
                e.view.spending_txid = None;
                e.view.spending_confirmations = 0;
                e.spend_height = None;
            }
        }
        self.height = to_height;
        Ok(())
    }

    fn rescan_from(&mut self, from_height: u32) -> RgbPqResult<()> {
        for e in self.entries.values_mut() {
            if matches!(e.spend_height, Some(h) if h >= from_height) {
                e.view.spending_confirmations = 0;
            }
        }
        Ok(())
    }

    fn set_tip(&mut self, tip: ChainTip) {
        self.height = tip.height;
        self.tip_hash = tip.hash;
    }
}

// =========================================================================
// SQLite indexer (persistent, feature-gated).
// =========================================================================

#[cfg(feature = "sqlite")]
/// Persistent (SQLite) indexer implementation.
pub mod sqlite {
    use super::*;
    use rgb_pq_core::{IndexError, RgbPqResult};
    use rgb_pq_seal::BtqOutpoint;
    use rusqlite::Connection;

    /// A persistent (SQLite) indexer. Suitable for longer-running services.
    pub struct SqliteIndexer {
        conn: Connection,
        height: u32,
        tip_hash: String,
    }

    impl SqliteIndexer {
        /// Open (or create) a SQLite indexer at `path`.
        pub fn open(path: &str) -> RgbPqResult<Self> {
            let conn =
                Connection::open(path).map_err(|e| IndexError::Persistence(e.to_string()))?;
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS outpoints (
                    k TEXT PRIMARY KEY,
                    txid TEXT NOT NULL,
                    vout INTEGER NOT NULL,
                    value INTEGER NOT NULL DEFAULT 0,
                    spk BLOB,
                    spent INTEGER NOT NULL DEFAULT 0,
                    spending_txid TEXT,
                    spending_confs INTEGER NOT NULL DEFAULT 0,
                    spend_height INTEGER
                );
                CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);",
            )
            .map_err(|e| IndexError::Persistence(e.to_string()))?;
            let (height, tip_hash) = read_meta(&conn)?;
            Ok(Self {
                conn,
                height,
                tip_hash,
            })
        }

        /// Open an in-memory SQLite indexer (useful for tests).
        pub fn open_memory() -> RgbPqResult<Self> {
            Self::open(":memory:")
        }
    }

    fn read_meta(conn: &Connection) -> RgbPqResult<(u32, String)> {
        let height: u32 = conn
            .query_row("SELECT v FROM meta WHERE k='height'", [], |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let tip = conn
            .query_row("SELECT v FROM meta WHERE k='tip'", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap_or_default();
        Ok((height, tip))
    }

    fn write_meta(conn: &Connection, height: u32, tip: &str) -> RgbPqResult<()> {
        conn.execute(
            "INSERT OR REPLACE INTO meta(k,v) VALUES('height',?1)",
            rusqlite::params![height.to_string()],
        )
        .map_err(|e| IndexError::Persistence(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO meta(k,v) VALUES('tip',?1)",
            rusqlite::params![tip],
        )
        .map_err(|e| IndexError::Persistence(e.to_string()))?;
        Ok(())
    }

    impl Indexer for SqliteIndexer {
        fn tip(&self) -> ChainTip {
            ChainTip {
                height: self.height,
                hash: self.tip_hash.clone(),
            }
        }

        fn watch(&mut self, outpoint: &BtqOutpoint) -> RgbPqResult<()> {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO outpoints(k,txid,vout) VALUES (?1,?2,?3)",
                    rusqlite::params![
                        key(outpoint),
                        outpoint.txid.to_string(),
                        outpoint.vout as i64
                    ],
                )
                .map_err(|e| IndexError::Persistence(e.to_string()))?;
            Ok(())
        }

        fn record_output(&mut self, outpoint: &BtqOutpoint, out: BtqTxOut) -> RgbPqResult<()> {
            self.conn
                .execute(
                    "UPDATE outpoints SET value=?1, spk=?2, spent=?3 WHERE k=?4",
                    rusqlite::params![
                        out.value as i64,
                        out.script_pubkey,
                        out.spent as i64,
                        key(outpoint),
                    ],
                )
                .map_err(|e| IndexError::Persistence(e.to_string()))?;
            Ok(())
        }

        fn record_spend(&mut self, outpoint: &BtqOutpoint, spending_tx: &BtqTx) -> RgbPqResult<()> {
            let confs = spending_tx.status.confirmations();
            self.conn
                .execute(
                    "UPDATE outpoints SET spending_txid=?1, spending_confs=?2, spend_height=?3 WHERE k=?4",
                    rusqlite::params![
                        spending_tx.txid,
                        confs as i64,
                        self.height as i64,
                        key(outpoint),
                    ],
                )
                .map_err(|e| IndexError::Persistence(e.to_string()))?;
            Ok(())
        }

        fn update_confirmations(&mut self, outpoint: &BtqOutpoint, depth: u32) -> RgbPqResult<()> {
            self.conn
                .execute(
                    "UPDATE outpoints SET spending_confs=?1 WHERE k=?2",
                    rusqlite::params![depth as i64, key(outpoint)],
                )
                .map_err(|e| IndexError::Persistence(e.to_string()))?;
            Ok(())
        }

        fn get(&self, outpoint: &BtqOutpoint) -> Option<&IndexedOutpoint> {
            // rusqlite requires &self mutation-free reads, but returning a
            // reference tied to the row lifetime is not possible without a
            // cache. The SqliteIndexer is a write-heavy cache; callers that
            // need a read view should use `get_owned`. We return None here to
            // force callers to the owned path (avoids an unsound borrow).
            let _ = outpoint;
            None
        }

        fn rollback(&mut self, to_height: u32) -> RgbPqResult<()> {
            self.conn
                .execute(
                    "UPDATE outpoints SET spending_txid=NULL, spending_confs=0, spend_height=NULL WHERE spend_height > ?1",
                    rusqlite::params![to_height as i64],
                )
                .map_err(|e| IndexError::Persistence(e.to_string()))?;
            self.height = to_height;
            write_meta(&self.conn, self.height, &self.tip_hash)?;
            Ok(())
        }

        fn rescan_from(&mut self, from_height: u32) -> RgbPqResult<()> {
            self.conn
                .execute(
                    "UPDATE outpoints SET spending_confs=0 WHERE spend_height >= ?1",
                    rusqlite::params![from_height as i64],
                )
                .map_err(|e| IndexError::Persistence(e.to_string()))?;
            Ok(())
        }

        fn set_tip(&mut self, tip: ChainTip) {
            self.height = tip.height;
            self.tip_hash = tip.hash.clone();
            let _ = write_meta(&self.conn, tip.height, &tip.hash);
        }
    }

    impl SqliteIndexer {
        /// Owned read of an outpoint's indexed facts (the SQLite read path).
        pub fn get_owned(&self, outpoint: &BtqOutpoint) -> RgbPqResult<Option<IndexedOutpoint>> {
            let mut stmt = self
                .conn
                .prepare("SELECT value, spk, spent, spending_txid, spending_confs FROM outpoints WHERE k=?1")
                .map_err(|e| IndexError::Persistence(e.to_string()))?;
            let row = stmt
                .query_row(rusqlite::params![key(outpoint)], |r| {
                    let value: i64 = r.get(0)?;
                    let spk: Vec<u8> = r.get(1)?;
                    let spent: i64 = r.get(2)?;
                    let spending_txid: Option<String> = r.get(3)?;
                    let confs: i64 = r.get(4)?;
                    Ok((value, spk, spent, spending_txid, confs))
                })
                .ok();
            match row {
                None => Ok(None),
                Some((value, spk, spent, spending_txid, confs)) => Ok(Some(IndexedOutpoint {
                    output: Some(BtqTxOut {
                        outpoint: *outpoint,
                        value: value as u64,
                        script_pubkey: spk,
                        spent: spent != 0,
                    }),
                    spending_txid,
                    spending_confirmations: confs as u32,
                })),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rgb_pq_seal::BtqTxid;

    fn outp(vout: u32) -> BtqOutpoint {
        BtqOutpoint::new(BtqTxid::from_bytes([0xaa; 32]), vout)
    }

    fn tx(id_byte: u8, confs: u32) -> BtqTx {
        BtqTx {
            txid: format!("{id_byte:02x}"),
            raw: vec![],
            status: if confs == 0 {
                TxStatus::Unconfirmed
            } else {
                TxStatus::Confirmed {
                    height: 100,
                    block_hash: "ab".into(),
                    confirmations: confs,
                    time: 0,
                }
            },
        }
    }

    #[test]
    fn mem_watch_record_get() {
        let mut idx = MemIndexer::new();
        idx.set_tip(ChainTip {
            height: 10,
            hash: "h".into(),
        });
        let o = outp(0);
        idx.watch(&o).unwrap();
        idx.record_spend(&o, &tx(1, 3)).unwrap();
        let e = idx.get(&o).unwrap();
        assert_eq!(e.spending_txid.as_deref(), Some("01"));
        assert_eq!(e.spending_confirmations, 3);
    }

    #[test]
    fn mem_rollback_drops_high_spends() {
        let mut idx = MemIndexer::new();
        idx.set_tip(ChainTip {
            height: 10,
            hash: "h".into(),
        });
        let o = outp(0);
        idx.watch(&o).unwrap();
        idx.record_spend(&o, &tx(1, 3)).unwrap();
        idx.rollback(5).unwrap();
        let e = idx.get(&o).unwrap();
        assert!(e.spending_txid.is_none());
        assert_eq!(e.spending_confirmations, 0);
    }

    #[test]
    fn mem_rescan_clears_confirmations() {
        let mut idx = MemIndexer::new();
        idx.set_tip(ChainTip {
            height: 10,
            hash: "h".into(),
        });
        let o = outp(0);
        idx.watch(&o).unwrap();
        idx.record_spend(&o, &tx(1, 3)).unwrap();
        idx.rescan_from(0).unwrap();
        let e = idx.get(&o).unwrap();
        assert_eq!(e.spending_confirmations, 0);
        assert!(e.spending_txid.is_some());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_persists_and_reads() {
        let mut idx = sqlite::SqliteIndexer::open_memory().unwrap();
        idx.set_tip(ChainTip {
            height: 7,
            hash: "h7".into(),
        });
        let o = outp(1);
        idx.watch(&o).unwrap();
        idx.record_output(
            &o,
            BtqTxOut {
                outpoint: o,
                value: 5000,
                script_pubkey: vec![0x6a, 0x00],
                spent: false,
            },
        )
        .unwrap();
        idx.record_spend(&o, &tx(2, 2)).unwrap();
        let v = idx.get_owned(&o).unwrap().unwrap();
        assert_eq!(v.spending_txid.as_deref(), Some("02"));
        assert_eq!(v.spending_confirmations, 2);
        idx.rollback(0).unwrap();
        let v = idx.get_owned(&o).unwrap().unwrap();
        assert!(v.spending_txid.is_none());
    }
}
