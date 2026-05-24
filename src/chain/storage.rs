use crate::chain::state::{UtxoEntry, UtxoMutation};
use crate::types::block::{Block, BlockHeader, HEADER_SIZE};
use crate::types::hash::Hash256;
use crate::types::transaction::{OutPoint, SerError, TxOutput};
use redb::{Builder, Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;

/// Storage errors.
#[derive(Debug)]
pub enum StorageError {
    Db(redb::Error),
    Serialization(SerError),
    Corruption(String),
}

impl From<redb::Error> for StorageError {
    fn from(e: redb::Error) -> Self {
        StorageError::Db(e)
    }
}

impl From<redb::TransactionError> for StorageError {
    fn from(e: redb::TransactionError) -> Self {
        StorageError::Db(e.into())
    }
}

impl From<redb::TableError> for StorageError {
    fn from(e: redb::TableError) -> Self {
        StorageError::Db(e.into())
    }
}

impl From<redb::StorageError> for StorageError {
    fn from(e: redb::StorageError) -> Self {
        StorageError::Db(e.into())
    }
}

impl From<redb::CommitError> for StorageError {
    fn from(e: redb::CommitError) -> Self {
        StorageError::Db(e.into())
    }
}

impl From<SerError> for StorageError {
    fn from(e: SerError) -> Self {
        StorageError::Serialization(e)
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Db(e) => write!(f, "storage error: {}", e),
            StorageError::Serialization(e) => write!(f, "serialization error: {}", e),
            StorageError::Corruption(msg) => write!(f, "database corruption: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

// Table definitions
const BLOCKS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const HEADERS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers");
const HEIGHT_INDEX: TableDefinition<u64, &[u8]> = TableDefinition::new("height_index");
const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const WORK_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("cumulative_work");
const SPENT_UTXOS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("spent_utxos");
const FORK_BLOCKS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("fork_blocks");
const IP_BAN_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ip_bans");
const ADDR_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("known_addrs");
const IDENTITY_BAN_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("identity_bans");
const RETAINED_FORK_HEADERS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("retained_fork_headers");
/// Maps tx_id (32 bytes) → block_height (u64) for O(1) transaction lookup.
const TX_INDEX_TABLE: TableDefinition<&[u8], u64> = TableDefinition::new("tx_index");
/// Phase 3a — persisted UTXO snapshot.
/// Key:   serialize_outpoint_key (36 bytes fixed: tx_id 32 | output_index u32 LE).
/// Value: serialize_utxo_entry   (output_len u32 LE | output_bytes | height u64 LE | is_coinbase u8).
const UTXOS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("utxos");
/// Phase 3b — reserved table for persisted SMT nodes (see issue #6).
/// Registered in `ChainStorage::open` so the table exists from first boot
/// of any 3a-aware build. Empty in 3a; 3b adds the writer + reader.
#[allow(dead_code)]
const SMT_NODES_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("smt_nodes");

const TIP_KEY: &str = "tip_block_id";
/// Phase 3a — set to [0x01] in the same write_txn that commits the final
/// snapshot rows. If absent or != [0x01] on boot, the snapshot is treated
/// as stale and `replay_chain` is used as the fallback / migration path.
#[allow(dead_code)] // writer wired in commit 6 (lazy migration).
const UTXO_SNAPSHOT_COMPLETE_KEY: &str = "utxo_snapshot_complete";
/// Phase 3a — 32-byte block_id at which the snapshot was finalized.
/// Open path trusts the snapshot only if this equals the current tip.
#[allow(dead_code)] // writer wired in commit 6 (lazy migration).
const UTXO_SNAPSHOT_TIP_KEY: &str = "utxo_snapshot_tip";

/// Serialize a list of spent UTXOs for storage.
/// Format: count(u32 LE) || for each: tx_id(32) | output_index(u32 LE) | serialized_output | height(u64 LE) | is_coinbase(u8)
fn serialize_spent_utxos(spent: &[(OutPoint, UtxoEntry)]) -> Result<Vec<u8>, SerError> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(spent.len() as u32).to_le_bytes());
    for (outpoint, entry) in spent {
        buf.extend_from_slice(outpoint.tx_id.as_bytes());
        buf.extend_from_slice(&outpoint.output_index.to_le_bytes());
        let output_bytes = entry.output.serialize()?;
        buf.extend_from_slice(&(output_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&output_bytes);
        buf.extend_from_slice(&entry.height.to_le_bytes());
        buf.push(if entry.is_coinbase { 1 } else { 0 });
    }
    Ok(buf)
}

/// Serialize a single UTXO entry for the Phase 3a UTXOS_TABLE.
/// Format: output_len(u32 LE) | output_bytes | height(u64 LE) | is_coinbase(u8).
/// Hand-rolled to match the rest of the storage layer (no bincode / serde).
fn serialize_utxo_entry(entry: &UtxoEntry) -> Result<Vec<u8>, SerError> {
    let output_bytes = entry.output.serialize()?;
    let mut buf = Vec::with_capacity(4 + output_bytes.len() + 8 + 1);
    buf.extend_from_slice(&(output_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&output_bytes);
    buf.extend_from_slice(&entry.height.to_le_bytes());
    buf.push(if entry.is_coinbase { 1 } else { 0 });
    Ok(buf)
}

/// Deserialize a single UTXO entry from the Phase 3a UTXOS_TABLE.
/// Returns None on any framing error (treat as corruption at the caller).
#[allow(dead_code)] // reader wired in commit 5 (open_chain).
fn deserialize_utxo_entry(data: &[u8]) -> Option<UtxoEntry> {
    if data.len() < 4 {
        return None;
    }
    let output_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let mut pos = 4;
    if pos + output_len > data.len() {
        return None;
    }
    let (output, consumed) = TxOutput::deserialize(&data[pos..pos + output_len]).ok()?;
    if consumed != output_len {
        return None;
    }
    pos += output_len;
    if pos + 9 != data.len() {
        return None; // exact-size frame; trailing bytes = corruption
    }
    let height = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
    let is_coinbase = data[pos + 8] != 0;
    Some(UtxoEntry {
        output,
        height,
        is_coinbase,
    })
}

/// Serialize an OutPoint as the fixed 36-byte UTXOS_TABLE key.
/// Layout: tx_id (32 bytes, raw) | output_index (u32 LE, 4 bytes).
fn serialize_outpoint_key(op: &OutPoint) -> [u8; 36] {
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(op.tx_id.as_bytes());
    buf[32..].copy_from_slice(&op.output_index.to_le_bytes());
    buf
}

/// Deserialize an OutPoint from a UTXOS_TABLE key.
/// Returns None if the slice is not exactly 36 bytes.
#[allow(dead_code)] // reader wired in commit 5 (open_chain).
fn deserialize_outpoint_key(data: &[u8]) -> Option<OutPoint> {
    if data.len() != 36 {
        return None;
    }
    let mut tx_id_bytes = [0u8; 32];
    tx_id_bytes.copy_from_slice(&data[..32]);
    let output_index = u32::from_le_bytes(data[32..].try_into().ok()?);
    Some(OutPoint::new(Hash256(tx_id_bytes), output_index))
}

/// Phase 3a — apply a mutation log to UTXOS_TABLE inside an existing
/// write transaction. Insert variants write the serialized entry;
/// Remove variants delete by key. Mutations are applied in order so the
/// final state matches the in-memory sequence (matters for tx_A creates,
/// tx_B in same block consumes intra-block dependencies).
fn apply_utxo_mutations(
    write_txn: &redb::WriteTransaction,
    mutations: &[UtxoMutation],
) -> Result<(), StorageError> {
    if mutations.is_empty() {
        return Ok(());
    }
    let mut utxos = write_txn.open_table(UTXOS_TABLE)?;
    for m in mutations {
        match m {
            UtxoMutation::Insert(op, entry) => {
                let key = serialize_outpoint_key(op);
                let value = serialize_utxo_entry(entry)?;
                utxos.insert(key.as_slice(), value.as_slice())?;
            }
            UtxoMutation::Remove(op, _entry) => {
                let key = serialize_outpoint_key(op);
                utxos.remove(key.as_slice())?;
            }
        }
    }
    Ok(())
}

/// Phase 3a — advance an existing complete snapshot's tip pointer inside an
/// already-open META_TABLE write handle. Called from `commit_block_atomic`
/// and `commit_reorg_atomic` so that every tip update on top of a known-
/// complete snapshot also moves the marker atomically (issue #6 reviewer
/// P1: a running node that processes any blocks between restarts must
/// still hit `open_chain`'s fast path).
///
/// **No-op when `UTXO_SNAPSHOT_COMPLETE_KEY` is absent.** A normal tip
/// update only writes that one block's mutations into UTXOS_TABLE — it
/// cannot truthfully promote a partial snapshot to "complete". Promoting
/// it anyway would trap a `--no-auto-migrate` operator: their first new
/// block would stamp a snapshot with one row's worth of UTXOs as
/// complete, and the next `open_chain` would hard-fail on the state_root
/// cross-check instead of falling back to replay as the help text
/// promises.
///
/// Snapshot initialization (genesis bootstrap and the migration-finalize
/// path) writes the COMPLETE key directly — see
/// `initialize_snapshot_marker_in_txn` and `finalize_utxo_snapshot`.
fn advance_snapshot_marker_in_txn(
    meta: &mut redb::Table<&'static str, &'static [u8]>,
    tip_id: &Hash256,
) -> Result<(), StorageError> {
    let already_complete = matches!(
        meta.get(UTXO_SNAPSHOT_COMPLETE_KEY)?,
        Some(v) if v.value() == [0x01u8]
    );
    if !already_complete {
        // Legacy datadir or post-`clear_utxo_snapshot` state: leave both
        // keys absent so `open_chain` keeps falling back to replay.
        return Ok(());
    }
    meta.insert(UTXO_SNAPSHOT_TIP_KEY, tip_id.as_bytes().as_ref())?;
    Ok(())
}

/// Phase 3a — initialize the snapshot marker for a known-complete on-disk
/// UTXO state. Used by `commit_genesis_atomic` (the genesis write
/// populates UTXOS_TABLE from the full genesis mutation log in the same
/// write_txn, so the snapshot is complete by construction) and pairs with
/// `finalize_utxo_snapshot` for the migration-backfill path.
///
/// Unconditionally writes both `UTXO_SNAPSHOT_TIP_KEY` and
/// `UTXO_SNAPSHOT_COMPLETE_KEY = [0x01]`. Subsequent
/// `advance_snapshot_marker_in_txn` calls then move the tip pointer
/// because COMPLETE is now set.
fn initialize_snapshot_marker_in_txn(
    meta: &mut redb::Table<&'static str, &'static [u8]>,
    tip_id: &Hash256,
) -> Result<(), StorageError> {
    meta.insert(UTXO_SNAPSHOT_TIP_KEY, tip_id.as_bytes().as_ref())?;
    meta.insert(UTXO_SNAPSHOT_COMPLETE_KEY, &[0x01u8][..])?;
    Ok(())
}

/// Deserialize a list of spent UTXOs from storage.
fn deserialize_spent_utxos(data: &[u8]) -> Option<Vec<(OutPoint, UtxoEntry)>> {
    if data.len() < 4 {
        return None;
    }
    let count = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let mut pos = 4;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 36 > data.len() {
            return None;
        }
        let mut tx_id_bytes = [0u8; 32];
        tx_id_bytes.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let output_index = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
        pos += 4;

        if pos + 4 > data.len() {
            return None;
        }
        let output_len = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if pos + output_len > data.len() {
            return None;
        }
        let (output, consumed) = TxOutput::deserialize(&data[pos..pos + output_len]).ok()?;
        if consumed != output_len {
            return None; // trailing bytes in output record = corruption
        }
        pos += output_len;

        if pos + 9 > data.len() {
            return None;
        }
        let height = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let is_coinbase = data[pos] != 0;
        pos += 1;

        let outpoint = OutPoint::new(Hash256(tx_id_bytes), output_index);
        result.push((
            outpoint,
            UtxoEntry {
                output,
                height,
                is_coinbase,
            },
        ));
    }
    if pos != data.len() {
        return None; // trailing bytes after all entries = corruption
    }
    Some(result)
}

/// Persistent storage for blocks and chain metadata.
pub struct ChainStorage {
    db: Arc<Database>,
}

#[allow(clippy::result_large_err)]
impl ChainStorage {
    /// Open or create the chain database at the given path.
    pub fn open(path: &Path) -> Result<Self, redb::Error> {
        // Cap redb's in-memory page cache at 256 MiB (default is 1 GiB).
        // On 4GB VPS machines, the default consumes too much RAM.
        const CACHE_SIZE_BYTES: usize = 256 * 1024 * 1024;
        let db = Builder::new()
            .set_cache_size(CACHE_SIZE_BYTES)
            .create(path)?;

        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(BLOCKS_TABLE)?;
            let _ = write_txn.open_table(HEADERS_TABLE)?;
            let _ = write_txn.open_table(HEIGHT_INDEX)?;
            let _ = write_txn.open_table(META_TABLE)?;
            let _ = write_txn.open_table(WORK_TABLE)?;
            let _ = write_txn.open_table(SPENT_UTXOS_TABLE)?;
            let _ = write_txn.open_table(FORK_BLOCKS_TABLE)?;
            let _ = write_txn.open_table(IP_BAN_TABLE)?;
            let _ = write_txn.open_table(ADDR_TABLE)?;
            let _ = write_txn.open_table(IDENTITY_BAN_TABLE)?;
            let _ = write_txn.open_table(RETAINED_FORK_HEADERS_TABLE)?;
            let _ = write_txn.open_table(TX_INDEX_TABLE)?;
            let _ = write_txn.open_table(UTXOS_TABLE)?;
            let _ = write_txn.open_table(SMT_NODES_TABLE)?;
        }
        write_txn.commit()?;

        Ok(ChainStorage { db: Arc::new(db) })
    }

    /// Store block data only (block bytes + header). Does NOT update height index.
    /// Use this when storing non-canonical (fork) blocks.
    #[allow(dead_code)]
    pub fn store_block(&self, block: &Block) -> Result<(), StorageError> {
        let block_id = block.header.block_id();
        let block_bytes = block.serialize()?;
        let header_bytes = block.header.serialize();

        let write_txn = self.db.begin_write()?;
        {
            let mut blocks = write_txn.open_table(BLOCKS_TABLE)?;
            blocks.insert(block_id.as_bytes().as_ref(), block_bytes.as_slice())?;

            let mut headers = write_txn.open_table(HEADERS_TABLE)?;
            headers.insert(block_id.as_bytes().as_ref(), header_bytes.as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Update the canonical height → block_id index for a specific height.
    #[allow(dead_code)]
    pub fn set_canonical_height(&self, height: u64, block_id: &Hash256) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;
        {
            let mut height_idx = write_txn.open_table(HEIGHT_INDEX)?;
            height_idx.insert(height, block_id.as_bytes().as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Store cumulative work for a block.
    ///
    /// Note: no production caller as of the chain-replay cleanup —
    /// `commit_block_atomic` writes WORK_TABLE inline in the same atomic
    /// transaction as the block itself. This standalone method is kept
    /// because integration test fixtures (`tests/audit_fix_tests_*`)
    /// construct chain state piece by piece and use it directly.
    #[allow(dead_code)]
    pub fn put_cumulative_work(
        &self,
        block_id: &Hash256,
        work: &[u8; 32],
    ) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(WORK_TABLE)?;
            table.insert(block_id.as_bytes().as_ref(), work.as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get cumulative work for a block.
    pub fn get_cumulative_work(&self, block_id: &Hash256) -> Result<Option<[u8; 32]>, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(WORK_TABLE)?;
        match table.get(block_id.as_bytes().as_ref())? {
            Some(data) => {
                let bytes = data.value();
                if bytes.len() == 32 {
                    let mut work = [0u8; 32];
                    work.copy_from_slice(bytes);
                    Ok(Some(work))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Store a block and update its canonical height index.
    /// Convenience method: store_block + set_canonical_height in one transaction.
    /// Used in tests; production code uses commit_genesis_atomic or commit_block_atomic.
    #[allow(dead_code)]
    pub fn put_block(&self, block: &Block) -> Result<(), StorageError> {
        let block_id = block.header.block_id();
        let block_bytes = block.serialize()?;
        let header_bytes = block.header.serialize();

        let write_txn = self.db.begin_write()?;
        {
            let mut blocks = write_txn.open_table(BLOCKS_TABLE)?;
            blocks.insert(block_id.as_bytes().as_ref(), block_bytes.as_slice())?;

            let mut headers = write_txn.open_table(HEADERS_TABLE)?;
            headers.insert(block_id.as_bytes().as_ref(), header_bytes.as_ref())?;

            let mut height_idx = write_txn.open_table(HEIGHT_INDEX)?;
            height_idx.insert(block.header.height, block_id.as_bytes().as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieve a block by its ID.
    ///
    /// Rejects records with trailing bytes after the deserialized block
    /// (fail-closed on corruption).
    pub fn get_block(&self, block_id: &Hash256) -> Result<Option<Block>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let blocks = read_txn.open_table(BLOCKS_TABLE)?;
        match blocks.get(block_id.as_bytes().as_ref())? {
            Some(data) => {
                let bytes = data.value();
                match Block::deserialize(bytes) {
                    Ok((block, consumed)) if consumed == bytes.len() => {
                        let actual_id = block.header.block_id();
                        if actual_id != *block_id {
                            return Err(StorageError::Corruption(format!(
                                "stored block does not match its key: expected {}, got {}",
                                block_id, actual_id
                            )));
                        }
                        Ok(Some(block))
                    }
                    _ => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// Look up which block height contains a given transaction ID.
    /// Returns None if the tx is not indexed (pre-index blocks or not on canonical chain).
    pub fn get_tx_block_height(&self, tx_id: &Hash256) -> Result<Option<u64>, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(TX_INDEX_TABLE) {
            Ok(t) => t,
            Err(_) => return Ok(None), // table doesn't exist yet (old DB)
        };
        match table.get(tx_id.as_bytes().as_ref())? {
            Some(data) => Ok(Some(data.value())),
            None => Ok(None),
        }
    }

    /// Index a single transaction ID → block height mapping.
    /// Used during startup replay to populate the tx index for pre-existing blocks.
    #[allow(dead_code)]
    pub fn index_tx(&self, tx_id: &Hash256, height: u64) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;
        {
            let mut tx_idx = write_txn.open_table(TX_INDEX_TABLE)?;
            tx_idx.insert(tx_id.as_bytes().as_ref(), height)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieve a block header by its ID.
    pub fn get_header(&self, block_id: &Hash256) -> Result<Option<BlockHeader>, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let headers = read_txn.open_table(HEADERS_TABLE)?;
        match headers.get(block_id.as_bytes().as_ref())? {
            Some(data) => {
                let bytes = data.value();
                if bytes.len() == HEADER_SIZE {
                    let arr: [u8; HEADER_SIZE] = bytes.try_into().unwrap();
                    Ok(Some(BlockHeader::deserialize(&arr)))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Get the block ID at a given height.
    pub fn get_block_id_by_height(&self, height: u64) -> Result<Option<Hash256>, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let height_idx = read_txn.open_table(HEIGHT_INDEX)?;
        match height_idx.get(height)? {
            Some(data) => {
                let bytes = data.value();
                if bytes.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(bytes);
                    Ok(Some(Hash256(hash)))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Set the current chain tip.
    #[allow(dead_code)]
    pub fn set_tip(&self, block_id: &Hash256) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;
        {
            let mut meta = write_txn.open_table(META_TABLE)?;
            meta.insert(TIP_KEY, block_id.as_bytes().as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get the current chain tip block ID.
    pub fn get_tip(&self) -> Result<Option<Hash256>, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let meta = read_txn.open_table(META_TABLE)?;
        match meta.get(TIP_KEY)? {
            Some(data) => {
                let bytes = data.value();
                if bytes.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(bytes);
                    Ok(Some(Hash256(hash)))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Check if a block exists in storage (full block body, not just header).
    pub fn has_block(&self, block_id: &Hash256) -> Result<bool, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let blocks = read_txn.open_table(BLOCKS_TABLE)?;
        Ok(blocks.get(block_id.as_bytes().as_ref())?.is_some())
    }

    /// Check if a header exists in storage (header only, not requiring the full block body).
    /// Returns true if the header is retained even after fork eviction.
    pub fn has_header(&self, block_id: &Hash256) -> Result<bool, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let headers = read_txn.open_table(HEADERS_TABLE)?;
        Ok(headers.get(block_id.as_bytes().as_ref())?.is_some())
    }

    /// Check if a block is tracked in FORK_BLOCKS_TABLE.
    /// Returns false if the entry was removed (e.g. by a concurrent canonical commit).
    pub fn is_fork_block(&self, block_id: &Hash256) -> Result<bool, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(FORK_BLOCKS_TABLE)?;
        Ok(table.get(block_id.as_bytes().as_ref())?.is_some())
    }

    /// Delete a canonical height → block_id entry (for clearing stale heights after reorg).
    #[allow(dead_code)]
    pub fn delete_canonical_height(&self, height: u64) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;
        {
            let mut height_idx = write_txn.open_table(HEIGHT_INDEX)?;
            height_idx.remove(height)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Store the UTXOs spent by a block (for undo during reorg).
    ///
    /// Note: no production caller as of the chain-replay cleanup —
    /// `commit_block_atomic` / `commit_reorg_atomic` write SPENT_UTXOS_TABLE
    /// inline in their atomic transactions. This standalone method is kept
    /// because integration test fixtures (`tests/audit_fix_tests_*`)
    /// construct chain state piece by piece and use it directly.
    #[allow(dead_code)]
    pub fn store_spent_utxos(
        &self,
        block_id: &Hash256,
        spent: &[(OutPoint, UtxoEntry)],
    ) -> Result<(), StorageError> {
        let data = serialize_spent_utxos(spent)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SPENT_UTXOS_TABLE)?;
            table.insert(block_id.as_bytes().as_ref(), data.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieve the UTXOs spent by a block (for undo during reorg).
    pub fn get_spent_utxos(
        &self,
        block_id: &Hash256,
    ) -> Result<Option<Vec<(OutPoint, UtxoEntry)>>, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SPENT_UTXOS_TABLE)?;
        match table.get(block_id.as_bytes().as_ref())? {
            Some(data) => {
                let bytes = data.value();
                Ok(deserialize_spent_utxos(bytes))
            }
            None => Ok(None),
        }
    }

    /// Phase 3a — read every persisted UTXO into a Vec.
    ///
    /// Consumed by commit 5 (open_chain).
    ///
    /// redb's `Table::iter()` is key-ordered (per redb docs), so calling
    /// this twice on the same datadir yields the same sequence — the
    /// `state_root_parity_across_two_open_chain_calls` test pins that
    /// invariant from the boot-path side.
    ///
    /// Returns `Err(StorageError::Corruption)` on any framing error
    /// rather than `Ok(partial)`; the open path treats this as
    /// "snapshot is corrupt, fall through to `replay_chain`".
    #[allow(dead_code)] // wired in commit 5 (open_chain).
    pub fn iter_utxos(&self) -> Result<Vec<(OutPoint, UtxoEntry)>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(UTXOS_TABLE)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            let op = deserialize_outpoint_key(k.value()).ok_or_else(|| {
                StorageError::Corruption(format!(
                    "UTXOS_TABLE key not a valid 36-byte OutPoint (len={})",
                    k.value().len()
                ))
            })?;
            let utxo = deserialize_utxo_entry(v.value()).ok_or_else(|| {
                StorageError::Corruption(format!(
                    "UTXOS_TABLE value for {:?} failed to deserialize",
                    op
                ))
            })?;
            out.push((op, utxo));
        }
        Ok(out)
    }

    /// Phase 3a — returns `Some(tip_id)` iff the snapshot was finalized:
    /// both `UTXO_SNAPSHOT_COMPLETE_KEY == [0x01]` AND
    /// `UTXO_SNAPSHOT_TIP_KEY` is set to a valid 32-byte block_id.
    ///
    /// Returns `None` in every other case (missing markers, partial
    /// write, length mismatch). Open path interprets `None` as "no
    /// trustworthy snapshot, run replay_chain".
    /// Phase 3a — finalize the UTXO snapshot: write every (OutPoint, UtxoEntry)
    /// pair from the in-memory `UtxoSet` into UTXOS_TABLE, then atomically
    /// set the two snapshot markers in META_TABLE. All inside a single redb
    /// write_txn so any crash before commit() leaves the markers absent and
    /// the next boot retries the backfill.
    ///
    /// Called once after the first successful `replay_chain` on a pre-3a
    /// datadir (see `open_chain`'s migration branch).
    ///
    /// Caller responsibility: only invoke when UTXOS_TABLE is empty (the
    /// first-iteration assumption). Resumable backfill from a partial write
    /// is a future enhancement — restart-from-scratch is the documented
    /// crash-recovery behavior for now.
    pub fn finalize_utxo_snapshot(
        &self,
        utxo_set: &crate::chain::state::UtxoSet,
        tip_id: &Hash256,
    ) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut tbl = write_txn.open_table(UTXOS_TABLE)?;
            for (op, entry) in utxo_set.iter() {
                let key = serialize_outpoint_key(op);
                let value = serialize_utxo_entry(entry)?;
                tbl.insert(key.as_slice(), value.as_slice())?;
            }
            let mut meta = write_txn.open_table(META_TABLE)?;
            meta.insert(UTXO_SNAPSHOT_COMPLETE_KEY, &[0x01u8][..])?;
            meta.insert(UTXO_SNAPSHOT_TIP_KEY, tip_id.as_bytes().as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Phase 3a — clear UTXOS_TABLE and both snapshot markers in a single
    /// write_txn. Used by:
    ///
    /// * `--rebuild-state` (reviewer P2): operator-invoked recovery for a
    ///   corrupt snapshot. The CLI flow is clear → `replay_chain` →
    ///   `finalize_utxo_snapshot`, all in a single boot.
    /// * Integration tests that need to simulate a "legacy pre-3a datadir"
    ///   state where the markers are absent but the canonical chain
    ///   (BLOCKS_TABLE / HEIGHT_INDEX / TIP_KEY) is intact.
    ///
    /// Does NOT touch any other table — the underlying chain data
    /// (`BLOCKS_TABLE`, `HEADERS_TABLE`, `HEIGHT_INDEX`, `WORK_TABLE`,
    /// `SPENT_UTXOS_TABLE`, `TIP_KEY`) is preserved, so subsequent
    /// `replay_chain` can rebuild the snapshot deterministically.
    pub fn clear_utxo_snapshot(&self) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut utxos = write_txn.open_table(UTXOS_TABLE)?;
            utxos.retain(|_, _| false)?;
            let mut meta = write_txn.open_table(META_TABLE)?;
            meta.remove(UTXO_SNAPSHOT_COMPLETE_KEY)?;
            meta.remove(UTXO_SNAPSHOT_TIP_KEY)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    #[allow(dead_code)] // wired in commit 5 (open_chain) and commit 6 (lazy migration).
    pub fn get_utxo_snapshot_tip(&self) -> Result<Option<Hash256>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(META_TABLE)?;
        let complete = match table.get(UTXO_SNAPSHOT_COMPLETE_KEY)? {
            Some(v) if v.value() == [0x01u8] => true,
            _ => false,
        };
        if !complete {
            return Ok(None);
        }
        let tip = match table.get(UTXO_SNAPSHOT_TIP_KEY)? {
            Some(v) if v.value().len() == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(v.value());
                Hash256(buf)
            }
            _ => return Ok(None),
        };
        Ok(Some(tip))
    }

    /// Evict a fork block: remove the heavy block body and fork tracking,
    /// but retain the header and cumulative work (188 bytes each) so that
    /// `expected_difficulty()` can still walk ancestor headers at retarget
    /// boundaries after deep reorgs.
    ///
    /// If the block was promoted to canonical, only the fork tracking
    /// entry is removed (data tables are preserved).
    pub fn evict_fork_block(&self, block_id: &Hash256) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            // Check if block was promoted to canonical (TOCTOU guard:
            // reading header + HEIGHT_INDEX inside the write transaction
            // serializes with commit_reorg_atomic).
            let headers = write_txn.open_table(HEADERS_TABLE)?;
            let height_opt: Option<u64> =
                headers
                    .get(block_id.as_bytes().as_ref())?
                    .and_then(|guard| {
                        let bytes = guard.value();
                        if bytes.len() >= 12 {
                            Some(u64::from_le_bytes(
                                bytes[4..12].try_into().expect("checked len"),
                            ))
                        } else {
                            None
                        }
                    });
            drop(headers);

            let is_canonical = match height_opt {
                Some(height) => {
                    let height_idx = write_txn.open_table(HEIGHT_INDEX)?;
                    let canonical = height_idx
                        .get(height)?
                        .map(|guard| guard.value() == block_id.as_bytes().as_ref())
                        .unwrap_or(false);
                    drop(height_idx);
                    canonical
                }
                None => false,
            };

            if !is_canonical {
                // Delete block body (heavy) but retain header + cumulative
                // work (188 bytes) — difficulty computation needs ancestor
                // headers at retarget boundaries.
                let mut blocks = write_txn.open_table(BLOCKS_TABLE)?;
                blocks.remove(block_id.as_bytes().as_ref())?;

                // Delete spent-UTXO undo metadata. These blobs are only
                // needed for undoing canonical blocks during reorg. Once a
                // block is evicted from fork storage it cannot be undone,
                // so the undo data is dead weight.
                let mut spent = write_txn.open_table(SPENT_UTXOS_TABLE)?;
                spent.remove(block_id.as_bytes().as_ref())?;

                // Track this retained header so we can cap total count.
                if let Some(height) = height_opt {
                    let mut retained = write_txn.open_table(RETAINED_FORK_HEADERS_TABLE)?;
                    retained.insert(block_id.as_bytes().as_ref(), height.to_le_bytes().as_ref())?;
                }
            }

            let mut fork_tbl = write_txn.open_table(FORK_BLOCKS_TABLE)?;
            fork_tbl.remove(block_id.as_bytes().as_ref())?;
        }
        write_txn.commit()?;

        self.enforce_retained_fork_header_cap(crate::types::MAX_RETAINED_FORK_HEADERS)?;
        Ok(())
    }

    /// Enforce the cap on retained non-canonical fork headers.
    /// When the count exceeds `max_retained`, evicts the lowest-height
    /// entries (deleting from RETAINED_FORK_HEADERS_TABLE, HEADERS_TABLE,
    /// and WORK_TABLE), skipping any block that has since become canonical.
    fn enforce_retained_fork_header_cap(&self, max_retained: u32) -> Result<(), StorageError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(RETAINED_FORK_HEADERS_TABLE)?;
        let mut entries: Vec<([u8; 32], u64)> = Vec::new();
        for entry in table.iter()? {
            let (key, val) = entry?;
            let key_bytes = key.value();
            let val_bytes = val.value();
            if key_bytes.len() == 32 && val_bytes.len() == 8 {
                let mut id = [0u8; 32];
                id.copy_from_slice(key_bytes);
                let height = u64::from_le_bytes(val_bytes.try_into().expect("checked len"));
                entries.push((id, height));
            }
        }
        drop(table);
        drop(read_txn);

        if entries.len() <= max_retained as usize {
            return Ok(());
        }

        // Sort by height ascending — evict lowest-height entries first
        entries.sort_by_key(|&(_, h)| h);
        let to_evict = entries.len() - max_retained as usize;

        let write_txn = self.db.begin_write()?;
        {
            let height_idx = write_txn.open_table(HEIGHT_INDEX)?;
            let mut retained = write_txn.open_table(RETAINED_FORK_HEADERS_TABLE)?;
            let mut headers = write_txn.open_table(HEADERS_TABLE)?;
            let mut work = write_txn.open_table(WORK_TABLE)?;
            let mut spent = write_txn.open_table(SPENT_UTXOS_TABLE)?;

            for &(ref id, height) in entries.iter().take(to_evict) {
                // Canonical guard: don't delete headers that were promoted
                let is_canonical = height_idx
                    .get(height)?
                    .map(|guard| guard.value() == id.as_ref())
                    .unwrap_or(false);
                if is_canonical {
                    // Just remove from retained tracker — data stays
                    retained.remove(id.as_ref())?;
                    continue;
                }
                retained.remove(id.as_ref())?;
                headers.remove(id.as_ref())?;
                work.remove(id.as_ref())?;
                spent.remove(id.as_ref())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Count of retained fork headers (test helper).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn retained_fork_header_count(&self) -> Result<usize, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(RETAINED_FORK_HEADERS_TABLE)?;
        let mut count = 0;
        for entry in table.iter()? {
            let _ = entry?;
            count += 1;
        }
        Ok(count)
    }

    /// Atomically store a non-winning fork block and its cumulative work.
    /// Combines store_block + put_cumulative_work in a single redb write
    /// transaction for crash consistency.
    pub fn store_fork_block_atomic(
        &self,
        block: &Block,
        cumulative_work: &[u8; 32],
    ) -> Result<(), StorageError> {
        let block_id = block.header.block_id();
        let block_bytes = block.serialize()?;
        let header_bytes = block.header.serialize();

        let write_txn = self.db.begin_write()?;
        {
            let mut blocks = write_txn.open_table(BLOCKS_TABLE)?;
            blocks.insert(block_id.as_bytes().as_ref(), block_bytes.as_slice())?;

            let mut headers = write_txn.open_table(HEADERS_TABLE)?;
            headers.insert(block_id.as_bytes().as_ref(), header_bytes.as_ref())?;

            let mut work = write_txn.open_table(WORK_TABLE)?;
            work.insert(block_id.as_bytes().as_ref(), cumulative_work.as_ref())?;

            let mut fork_tbl = write_txn.open_table(FORK_BLOCKS_TABLE)?;
            fork_tbl.insert(block_id.as_bytes().as_ref(), cumulative_work.as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Atomically store the genesis block, its cumulative work, and the tip pointer
    /// in a single redb write transaction. A crash between any of these writes
    /// cannot leave the database in a half-initialized state.
    ///
    /// `utxo_mutations` is the mutation log emitted by applying the genesis
    /// transactions to a fresh UtxoSet. Persisted to UTXOS_TABLE inside the
    /// same write_txn so the on-disk snapshot is born consistent.
    pub fn commit_genesis_atomic(
        &self,
        block: &Block,
        cumulative_work: &[u8; 32],
        utxo_mutations: &[UtxoMutation],
    ) -> Result<(), StorageError> {
        let block_id = block.header.block_id();
        let block_bytes = block.serialize()?;
        let header_bytes = block.header.serialize();

        let write_txn = self.db.begin_write()?;
        {
            let mut blocks = write_txn.open_table(BLOCKS_TABLE)?;
            blocks.insert(block_id.as_bytes().as_ref(), block_bytes.as_slice())?;

            let mut headers = write_txn.open_table(HEADERS_TABLE)?;
            headers.insert(block_id.as_bytes().as_ref(), header_bytes.as_ref())?;

            let mut height_idx = write_txn.open_table(HEIGHT_INDEX)?;
            height_idx.insert(block.header.height, block_id.as_bytes().as_ref())?;

            let mut work = write_txn.open_table(WORK_TABLE)?;
            work.insert(block_id.as_bytes().as_ref(), cumulative_work.as_ref())?;

            let mut meta = write_txn.open_table(META_TABLE)?;
            meta.insert(TIP_KEY, block_id.as_bytes().as_ref())?;

            // Phase 3a — fresh-datadir bootstrap seeds UTXOS_TABLE from the
            // full genesis mutation log below in this same write_txn, so the
            // on-disk snapshot is complete by construction. Initialize both
            // marker keys; subsequent commit_block_atomic / commit_reorg_atomic
            // calls then advance just the tip pointer.
            initialize_snapshot_marker_in_txn(&mut meta, &block_id)?;

            // Index genesis transaction IDs
            let mut tx_idx = write_txn.open_table(TX_INDEX_TABLE)?;
            for tx in &block.transactions {
                if let Ok(tid) = tx.tx_id() {
                    tx_idx.insert(tid.as_bytes().as_ref(), block.header.height)?;
                }
            }

            // Phase 3a — seed UTXOS_TABLE from the genesis mutation log.
            apply_utxo_mutations(&write_txn, utxo_mutations)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Atomically commit a new canonical block (extends-tip path).
    /// Performs store_block + cumulative_work + spent_utxos + canonical_height
    /// + tip + UTXO mutations in a single redb write transaction for crash
    /// consistency.
    ///
    /// `utxo_mutations` is the mutation log returned by
    /// `validate_and_apply_block_transactions_atomic` for this block.
    /// Phase 3a (issue #6) — single source of truth: the same Vec that
    /// mutated the in-memory UtxoSet also mutates UTXOS_TABLE here.
    pub fn commit_block_atomic(
        &self,
        block: &Block,
        cumulative_work: &[u8; 32],
        spent_utxos: &[(OutPoint, UtxoEntry)],
        utxo_mutations: &[UtxoMutation],
    ) -> Result<(), StorageError> {
        let block_id = block.header.block_id();
        let block_bytes = block.serialize()?;
        let header_bytes = block.header.serialize();
        let spent_data = serialize_spent_utxos(spent_utxos)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut blocks = write_txn.open_table(BLOCKS_TABLE)?;
            blocks.insert(block_id.as_bytes().as_ref(), block_bytes.as_slice())?;

            let mut headers = write_txn.open_table(HEADERS_TABLE)?;
            headers.insert(block_id.as_bytes().as_ref(), header_bytes.as_ref())?;

            let mut work = write_txn.open_table(WORK_TABLE)?;
            work.insert(block_id.as_bytes().as_ref(), cumulative_work.as_ref())?;

            let mut spent = write_txn.open_table(SPENT_UTXOS_TABLE)?;
            spent.insert(block_id.as_bytes().as_ref(), spent_data.as_slice())?;

            let mut height_idx = write_txn.open_table(HEIGHT_INDEX)?;
            height_idx.insert(block.header.height, block_id.as_bytes().as_ref())?;

            let mut meta = write_txn.open_table(META_TABLE)?;
            meta.insert(TIP_KEY, block_id.as_bytes().as_ref())?;

            // Phase 3a — advance the snapshot marker atomically with TIP_KEY
            // so a running node's first restart after a new block still hits
            // the open_chain fast path. apply_utxo_mutations below keeps
            // UTXOS_TABLE in lockstep with the in-memory UtxoSet.
            advance_snapshot_marker_in_txn(&mut meta, &block_id)?;

            // Block is now canonical — remove from fork tracker
            let mut fork_tbl = write_txn.open_table(FORK_BLOCKS_TABLE)?;
            fork_tbl.remove(block_id.as_bytes().as_ref())?;

            // Index all transaction IDs in this block for O(1) lookup
            let mut tx_idx = write_txn.open_table(TX_INDEX_TABLE)?;
            for tx in &block.transactions {
                if let Ok(tid) = tx.tx_id() {
                    tx_idx.insert(tid.as_bytes().as_ref(), block.header.height)?;
                }
            }

            // Phase 3a — keep UTXOS_TABLE in lockstep with the in-memory set.
            apply_utxo_mutations(&write_txn, utxo_mutations)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Atomically commit a reorg.
    /// Stores all new-chain blocks (trigger + promoted ancestors), writes
    /// cumulative work, spent UTXOs for each new-chain block, canonical
    /// height index updates, stale height deletions, and tip — all in a
    /// single redb write transaction for crash consistency.
    ///
    /// All new-chain blocks are (re-)inserted into BLOCKS_TABLE/HEADERS_TABLE
    /// to prevent a race where fork eviction deletes an ancestor's data
    /// between the reorg walk and this commit.
    /// Phase 3a — `old_chain_blocks` is the list of orphaned blocks (the
    /// reorg's losing branch, in any order — UTXOS_TABLE undo iterates them
    /// regardless of order since each block's effect is reversible
    /// independently). For each orphan: outputs are removed from
    /// UTXOS_TABLE (looked up from the block body) and previously-spent
    /// UTXOs are re-inserted (read from the existing SPENT_UTXOS_TABLE
    /// row — same source the in-memory `undo_block_transactions` uses, so
    /// no drift between in-memory and on-disk views).
    ///
    /// `new_chain_mutations` is aligned to `new_chain_blocks` (oldest-first)
    /// and contains each block's full mutation log from
    /// `validate_and_apply_block_transactions_atomic`. UTXOS_TABLE
    /// forward-applies these inside the same write_txn, keeping the
    /// in-memory UtxoSet and on-disk snapshot in lockstep.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_reorg_atomic(
        &self,
        trigger_block: &Block,
        cumulative_work: &[u8; 32],
        old_chain_blocks: &[Block],
        new_chain_spent: &[(Hash256, Vec<(OutPoint, UtxoEntry)>)],
        new_chain_mutations: &[(Hash256, Vec<UtxoMutation>)],
        new_chain_heights: &[(u64, Hash256)],
        new_chain_blocks: &[Block],
        new_chain_work: &[(Hash256, [u8; 32])],
        stale_height_start: Option<u64>,
        stale_height_end: Option<u64>,
        new_tip_id: &Hash256,
    ) -> Result<(), StorageError> {
        let trigger_block_id = trigger_block.header.block_id();
        let block_bytes = trigger_block.serialize()?;
        let header_bytes = trigger_block.header.serialize();

        let write_txn = self.db.begin_write()?;
        {
            let mut blocks = write_txn.open_table(BLOCKS_TABLE)?;
            let mut headers = write_txn.open_table(HEADERS_TABLE)?;

            // Store the trigger block
            blocks.insert(trigger_block_id.as_bytes().as_ref(), block_bytes.as_slice())?;
            headers.insert(trigger_block_id.as_bytes().as_ref(), header_bytes.as_ref())?;

            // Re-insert all promoted ancestor blocks so that HEIGHT_INDEX
            // entries always point to existing block data, even if concurrent
            // fork eviction deleted an ancestor between the reorg walk and
            // this commit.
            for blk in new_chain_blocks {
                let blk_id = blk.header.block_id();
                let blk_bytes = blk.serialize()?;
                let hdr_bytes = blk.header.serialize();
                blocks.insert(blk_id.as_bytes().as_ref(), blk_bytes.as_slice())?;
                headers.insert(blk_id.as_bytes().as_ref(), hdr_bytes.as_ref())?;
            }

            let mut work = write_txn.open_table(WORK_TABLE)?;
            work.insert(
                trigger_block_id.as_bytes().as_ref(),
                cumulative_work.as_ref(),
            )?;

            // Restore cumulative work for all promoted ancestors.
            // Fork eviction (evict_fork_block) deletes WORK_TABLE
            // entries for non-canonical blocks. Without this, a promoted
            // ancestor could exist without work metadata, causing valid
            // descendant blocks to be rejected (parent work not found).
            for (blk_id, blk_work) in new_chain_work {
                work.insert(blk_id.as_bytes().as_ref(), blk_work.as_ref())?;
            }

            let mut spent_table = write_txn.open_table(SPENT_UTXOS_TABLE)?;
            for (blk_id, utxos) in new_chain_spent {
                let data = serialize_spent_utxos(utxos)?;
                spent_table.insert(blk_id.as_bytes().as_ref(), data.as_slice())?;
            }

            let mut height_idx = write_txn.open_table(HEIGHT_INDEX)?;

            // Remove stale-chain tx index entries BEFORE overwriting heights.
            // This must happen first so we read the OLD block IDs at each height,
            // including heights that overlap with the new chain.
            let mut tx_idx = write_txn.open_table(TX_INDEX_TABLE)?;
            {
                // Collect all heights that will be replaced or removed:
                // the stale tail plus any overlapping heights from new_chain_heights.
                let mut stale_heights: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
                if let (Some(start), Some(end)) = (stale_height_start, stale_height_end) {
                    for h in start..=end {
                        stale_heights.insert(h);
                    }
                }
                for (h, _) in new_chain_heights.iter() {
                    stale_heights.insert(*h);
                }
                for h in &stale_heights {
                    if let Ok(Some(old_bid_guard)) = height_idx.get(*h) {
                        let old_bid_bytes: Vec<u8> = old_bid_guard.value().to_vec();
                        drop(old_bid_guard);
                        if let Ok(Some(old_block_guard)) = blocks.get(old_bid_bytes.as_slice()) {
                            let old_block_bytes: Vec<u8> = old_block_guard.value().to_vec();
                            drop(old_block_guard);
                            if let Ok((old_block, _)) = Block::deserialize(&old_block_bytes) {
                                for tx in &old_block.transactions {
                                    if let Ok(tid) = tx.tx_id() {
                                        tx_idx.remove(tid.as_bytes().as_ref())?;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Now write new chain heights (overwrites overlapping entries)
            for (height, blk_id) in new_chain_heights {
                height_idx.insert(*height, blk_id.as_bytes().as_ref())?;
            }

            // Delete stale heights above new tip (non-overlapping tail)
            if let (Some(start), Some(end)) = (stale_height_start, stale_height_end) {
                for h in start..=end {
                    height_idx.remove(h)?;
                }
            }

            let mut meta = write_txn.open_table(META_TABLE)?;
            meta.insert(TIP_KEY, new_tip_id.as_bytes().as_ref())?;

            // Phase 3a — advance the snapshot marker atomically with the new
            // tip. UTXOS_TABLE is reconciled with the post-reorg in-memory
            // set in the two passes below (undo orphans + forward-apply new
            // chain), all inside this same write_txn.
            advance_snapshot_marker_in_txn(&mut meta, new_tip_id)?;

            // Promoted blocks are now canonical — remove from fork tracker
            let mut fork_tbl = write_txn.open_table(FORK_BLOCKS_TABLE)?;
            for (_, blk_id) in new_chain_heights {
                fork_tbl.remove(blk_id.as_bytes().as_ref())?;
            }
            // Also remove the trigger block itself
            fork_tbl.remove(trigger_block_id.as_bytes().as_ref())?;

            // Index tx IDs for trigger block + all promoted ancestors
            for tx in &trigger_block.transactions {
                if let Ok(tid) = tx.tx_id() {
                    tx_idx.insert(tid.as_bytes().as_ref(), trigger_block.header.height)?;
                }
            }
            for blk in new_chain_blocks {
                for tx in &blk.transactions {
                    if let Ok(tid) = tx.tx_id() {
                        tx_idx.insert(tid.as_bytes().as_ref(), blk.header.height)?;
                    }
                }
            }

            // Phase 3a — keep UTXOS_TABLE consistent with the post-reorg
            // in-memory UtxoSet. Two passes inside the same write_txn:
            //
            // 1. Undo orphans on disk by reversing their per-block effect:
            //    remove every output (block body), re-insert every spent
            //    UTXO (read from SPENT_UTXOS_TABLE — same source the
            //    in-memory undo_block_transactions reads, so the two
            //    derivations cannot drift).
            //
            // 2. Apply new chain mutations forward via the same helper that
            //    commit_block_atomic uses, in oldest-first order.
            {
                // SPENT_UTXOS_TABLE was already opened above (line ~1155) for
                // the new-chain write phase; redb forbids opening the same
                // table twice in one write_txn. Reuse the outer `spent_table`
                // handle here for the orphan-undo read phase. Pre-fix this
                // path errored with "Table 'spent_utxos' already opened" the
                // first time a real reorg fired during IBD.
                let mut utxos = write_txn.open_table(UTXOS_TABLE)?;
                for orphan in old_chain_blocks {
                    let orphan_id = orphan.header.block_id();
                    for tx in &orphan.transactions {
                        let tx_id = match tx.tx_id() {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        for (idx, _) in tx.outputs.iter().enumerate() {
                            let op = OutPoint::new(tx_id, idx as u32);
                            let key = serialize_outpoint_key(&op);
                            utxos.remove(key.as_slice())?;
                        }
                    }
                    // Restore inputs the orphan had consumed.
                    if let Some(spent_guard) = spent_table.get(orphan_id.as_bytes().as_ref())? {
                        let bytes = spent_guard.value();
                        if let Some(spent) = deserialize_spent_utxos(bytes) {
                            for (op, entry) in spent {
                                let key = serialize_outpoint_key(&op);
                                let value = serialize_utxo_entry(&entry)?;
                                utxos.insert(key.as_slice(), value.as_slice())?;
                            }
                        } else {
                            return Err(StorageError::Corruption(format!(
                                "SPENT_UTXOS_TABLE entry for orphan {} failed to deserialize",
                                orphan_id
                            )));
                        }
                    }
                    // Orphans with no spent_utxos row (e.g. coinbase-only
                    // historical blocks) are fine — nothing to restore.
                }
                drop(utxos);
            }
            for (_blk_id, mutations) in new_chain_mutations {
                apply_utxo_mutations(&write_txn, mutations)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get ancestor timestamps (up to `count` most recent) for MTP calculation.
    /// Returns timestamps ordered most-recent-first.
    pub fn get_ancestor_timestamps(
        &self,
        block_id: &Hash256,
        count: usize,
    ) -> Result<Vec<u64>, redb::Error> {
        let mut timestamps = Vec::with_capacity(count);
        let mut current_id = *block_id;

        for _ in 0..count {
            match self.get_header(&current_id)? {
                Some(header) => {
                    timestamps.push(header.timestamp);
                    if header.prev_block_id == Hash256::ZERO {
                        break;
                    }
                    current_id = header.prev_block_id;
                }
                None => break,
            }
        }

        Ok(timestamps)
    }

    /// Load fork block entries (block_id, cumulative_work) from the
    /// durable FORK_BLOCKS_TABLE. Used at startup to restore the in-memory
    /// fork_blocks Vec so the cap is enforced across restarts.
    ///
    /// If the table contains more than `max_entries`, only the highest-work
    /// entries are returned (defense-in-depth for crash-between-evict-and-
    /// remove edge cases). Excess entries are removed from the table.
    pub fn load_fork_blocks(
        &self,
        max_entries: u32,
    ) -> Result<Vec<(Hash256, [u8; 32])>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(FORK_BLOCKS_TABLE)?;
        let mut result = Vec::new();
        for entry in table.iter()? {
            let (key, val) = entry?;
            let key_bytes = key.value();
            let val_bytes = val.value();
            if key_bytes.len() == 32 && val_bytes.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(key_bytes);
                let mut work = [0u8; 32];
                work.copy_from_slice(val_bytes);
                result.push((Hash256(id), work));
            }
        }
        drop(table);
        drop(read_txn);

        if result.len() > max_entries as usize {
            // Sort by work descending (big-endian [u8;32], lexicographic = numeric)
            result.sort_by(|a, b| b.1.cmp(&a.1));
            // Evict excess entries: full deletion (all four tables).
            let excess: Vec<Hash256> = result[max_entries as usize..]
                .iter()
                .map(|(id, _)| *id)
                .collect();
            for id in &excess {
                self.evict_fork_block(id)?;
            }
            result.truncate(max_entries as usize);
        }
        // Sort by work ascending so in-memory ordering is deterministic
        // across restarts (lowest-work first, consistent with min-work eviction).
        result.sort_by(|a, b| a.1.cmp(&b.1));
        Ok(result)
    }

    // ── IP ban persistence (P2a) ──

    /// Persist an IP ban. Key: 16-byte canonical IP (v4 → v4-mapped-v6). Value: u64 LE ban expiry unix timestamp.
    pub fn put_ip_ban(
        &self,
        ip: std::net::IpAddr,
        banned_until_unix: u64,
    ) -> Result<(), StorageError> {
        let key = ip_to_canonical_bytes(ip);
        let val = banned_until_unix.to_le_bytes();
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(IP_BAN_TABLE)?;
            table.insert(key.as_ref(), val.as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Remove an IP ban entry.
    pub fn remove_ip_ban(&self, ip: std::net::IpAddr) -> Result<(), StorageError> {
        let key = ip_to_canonical_bytes(ip);
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(IP_BAN_TABLE)?;
            table.remove(key.as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Load all IP bans. Filters expired entries and deletes them during load.
    pub fn load_ip_bans(&self) -> Result<Vec<(std::net::IpAddr, u64)>, StorageError> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut result = Vec::new();
        let mut expired_keys = Vec::new();

        {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(IP_BAN_TABLE)?;
            for entry in table.iter()? {
                let (key, val) = entry?;
                let key_bytes = key.value();
                let val_bytes = val.value();
                if key_bytes.len() == 16 && val_bytes.len() == 8 {
                    let banned_until = u64::from_le_bytes(val_bytes.try_into().unwrap());
                    if banned_until > now_unix {
                        let ip = ip_from_canonical_bytes(key_bytes);
                        result.push((ip, banned_until));
                    } else {
                        expired_keys.push(key_bytes.to_vec());
                    }
                }
            }
        }

        // Clean up expired entries
        if !expired_keys.is_empty() {
            if let Ok(write_txn) = self.db.begin_write() {
                if let Ok(mut table) = write_txn.open_table(IP_BAN_TABLE) {
                    for key in &expired_keys {
                        let _ = table.remove(key.as_slice());
                    }
                }
                let _ = write_txn.commit();
            }
        }

        Ok(result)
    }

    // ── Known address persistence (P1b) ──

    /// Replace all known addresses atomically (clear + write).
    /// Key: 18-byte (16-byte IP + 2-byte port LE). Value: 8-byte last_seen LE.
    /// This prevents unbounded growth from addr-rotation/poisoning.
    pub fn put_known_addrs(
        &self,
        addrs: &[(std::net::SocketAddr, u64)],
    ) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(ADDR_TABLE)?;
            // Clear all existing entries before writing to prevent unbounded growth.
            // Collect keys first to avoid borrowing conflicts.
            let existing_keys: Vec<[u8; 18]> = table
                .iter()?
                .filter_map(|entry| {
                    let (key, _) = entry.ok()?;
                    let bytes = key.value();
                    if bytes.len() == 18 {
                        let mut arr = [0u8; 18];
                        arr.copy_from_slice(bytes);
                        Some(arr)
                    } else {
                        None
                    }
                })
                .collect();
            for key in &existing_keys {
                let _ = table.remove(key.as_ref());
            }

            for (addr, last_seen) in addrs {
                let key = socket_addr_to_bytes(addr);
                let val = last_seen.to_le_bytes();
                table.insert(key.as_ref(), val.as_ref())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Load known addresses, capped to `MAX_ADDR_BOOK_SIZE` by most recent `last_seen`.
    pub fn get_known_addrs(&self) -> Result<Vec<(std::net::SocketAddr, u64)>, StorageError> {
        use crate::types::MAX_ADDR_BOOK_SIZE;
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ADDR_TABLE)?;
        let mut result = Vec::new();
        for entry in table.iter()? {
            let (key, val) = entry?;
            let key_bytes = key.value();
            let val_bytes = val.value();
            if key_bytes.len() == 18 && val_bytes.len() == 8 {
                let addr = socket_addr_from_bytes(key_bytes);
                let last_seen = u64::from_le_bytes(val_bytes.try_into().unwrap());
                result.push((addr, last_seen));
            }
        }
        // Cap to MAX_ADDR_BOOK_SIZE, keeping entries with the most recent last_seen
        if result.len() > MAX_ADDR_BOOK_SIZE {
            result.sort_by(|a, b| b.1.cmp(&a.1)); // descending by last_seen
            result.truncate(MAX_ADDR_BOOK_SIZE);
        }
        Ok(result)
    }

    // ── Identity ban persistence ──

    /// Persist an identity ban. Key: 32-byte Ed25519 pubkey. Value: u64 LE ban expiry unix timestamp.
    pub fn put_identity_ban(
        &self,
        pubkey: &[u8; 32],
        banned_until_unix: u64,
    ) -> Result<(), StorageError> {
        let val = banned_until_unix.to_le_bytes();
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(IDENTITY_BAN_TABLE)?;
            table.insert(pubkey.as_ref(), val.as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Remove an identity ban entry.
    pub fn remove_identity_ban(&self, pubkey: &[u8; 32]) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(IDENTITY_BAN_TABLE)?;
            table.remove(pubkey.as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Load all identity bans. Filters expired entries and deletes them during load.
    pub fn load_identity_bans(&self) -> Result<Vec<([u8; 32], u64)>, StorageError> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut result = Vec::new();
        let mut expired_keys = Vec::new();

        {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(IDENTITY_BAN_TABLE)?;
            for entry in table.iter()? {
                let (key, val) = entry?;
                let key_bytes = key.value();
                let val_bytes = val.value();
                if key_bytes.len() == 32 && val_bytes.len() == 8 {
                    let banned_until = u64::from_le_bytes(val_bytes.try_into().unwrap());
                    if banned_until > now_unix {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(key_bytes);
                        result.push((pk, banned_until));
                    } else {
                        expired_keys.push(key_bytes.to_vec());
                    }
                }
            }
        }

        if !expired_keys.is_empty() {
            if let Ok(write_txn) = self.db.begin_write() {
                if let Ok(mut table) = write_txn.open_table(IDENTITY_BAN_TABLE) {
                    for key in &expired_keys {
                        let _ = table.remove(key.as_slice());
                    }
                }
                let _ = write_txn.commit();
            }
        }

        Ok(result)
    }

    /// v1.9.2: wipe all persisted IP bans. Used by `--purge-bans` operator
    /// recovery to clear bans accumulated under v1.8.x/v1.9.x before the
    /// empty-batch IBD-cascade fix.
    ///
    /// Iteration errors propagate; this is the operator recovery path, so
    /// silently skipping bad entries would leave bans in place and defeat
    /// the purpose. Caller must surface the failure.
    pub fn clear_ip_bans(&self) -> Result<usize, StorageError> {
        let keys: Vec<Vec<u8>> = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(IP_BAN_TABLE)?;
            let mut out = Vec::new();
            for entry in table.iter()? {
                let (k, _) = entry?;
                out.push(k.value().to_vec());
            }
            out
        };
        let count = keys.len();
        if count > 0 {
            let write_txn = self.db.begin_write()?;
            {
                let mut table = write_txn.open_table(IP_BAN_TABLE)?;
                for key in &keys {
                    table.remove(key.as_slice())?;
                }
            }
            write_txn.commit()?;
        }
        Ok(count)
    }

    /// v1.9.2: wipe all persisted identity bans. See `clear_ip_bans`.
    ///
    /// Iteration errors propagate, same rationale as `clear_ip_bans`.
    pub fn clear_identity_bans(&self) -> Result<usize, StorageError> {
        let keys: Vec<Vec<u8>> = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(IDENTITY_BAN_TABLE)?;
            let mut out = Vec::new();
            for entry in table.iter()? {
                let (k, _) = entry?;
                out.push(k.value().to_vec());
            }
            out
        };
        let count = keys.len();
        if count > 0 {
            let write_txn = self.db.begin_write()?;
            {
                let mut table = write_txn.open_table(IDENTITY_BAN_TABLE)?;
                for key in &keys {
                    table.remove(key.as_slice())?;
                }
            }
            write_txn.commit()?;
        }
        Ok(count)
    }

    /// Check if the HEIGHT_INDEX table is empty (no blocks indexed).
    pub fn height_index_is_empty(&self) -> Result<bool, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(HEIGHT_INDEX)?;
        let is_empty = table.iter()?.next().is_none();
        Ok(is_empty)
    }

    /// Returns true if the blocks table contains no entries.
    pub fn blocks_table_is_empty(&self) -> Result<bool, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(BLOCKS_TABLE)?;
        let is_empty = table.iter()?.next().is_none();
        Ok(is_empty)
    }

    /// Check if HEIGHT_INDEX contains any entries above `tip_height`.
    /// Returns true if stale entries exist (database corruption indicator).
    pub fn has_stale_height_entries(&self, tip_height: u64) -> Result<bool, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(HEIGHT_INDEX)?;
        let start = tip_height.saturating_add(1);
        let has_stale = table.range(start..)?.next().is_some();
        Ok(has_stale)
    }
}

/// Convert an IP address to 16-byte canonical form (v4 → v4-mapped-v6).
fn ip_to_canonical_bytes(ip: std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}

/// Convert 16-byte canonical form back to IpAddr.
fn ip_from_canonical_bytes(bytes: &[u8]) -> std::net::IpAddr {
    let v6 = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap());
    match v6.to_ipv4_mapped() {
        Some(v4) => std::net::IpAddr::V4(v4),
        None => std::net::IpAddr::V6(v6),
    }
}

/// Convert a SocketAddr to 18-byte key (16-byte canonical IP + 2-byte port LE).
fn socket_addr_to_bytes(addr: &std::net::SocketAddr) -> [u8; 18] {
    let mut buf = [0u8; 18];
    buf[0..16].copy_from_slice(&ip_to_canonical_bytes(addr.ip()));
    buf[16..18].copy_from_slice(&addr.port().to_le_bytes());
    buf
}

/// Convert 18-byte key back to SocketAddr.
fn socket_addr_from_bytes(bytes: &[u8]) -> std::net::SocketAddr {
    let ip = ip_from_canonical_bytes(&bytes[0..16]);
    let port = u16::from_le_bytes([bytes[16], bytes[17]]);
    std::net::SocketAddr::new(ip, port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
    use tempfile::TempDir;

    fn test_block() -> Block {
        let coinbase = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(10_000_000_000, &[1u8; 32])],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };

        Block {
            header: BlockHeader {
                version: 1,
                height: 0,
                prev_block_id: Hash256::ZERO,
                timestamp: 1700000000,
                difficulty_target: Hash256([0xFF; 32]),
                nonce: 42,
                tx_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
            },
            transactions: vec![coinbase],
        }
    }

    #[test]
    fn test_store_and_retrieve_block() {
        let tmpdir = TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&db_path).unwrap();

        let block = test_block();
        let block_id = block.header.block_id();

        storage.put_block(&block).unwrap();

        let retrieved = storage.get_block(&block_id).unwrap().unwrap();
        assert_eq!(retrieved, block);
    }

    #[test]
    fn test_get_header() {
        let tmpdir = TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&db_path).unwrap();

        let block = test_block();
        let block_id = block.header.block_id();
        storage.put_block(&block).unwrap();

        let header = storage.get_header(&block_id).unwrap().unwrap();
        assert_eq!(header, block.header);
    }

    #[test]
    fn test_height_index() {
        let tmpdir = TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&db_path).unwrap();

        let block = test_block();
        let block_id = block.header.block_id();
        storage.put_block(&block).unwrap();

        let retrieved_id = storage.get_block_id_by_height(0).unwrap().unwrap();
        assert_eq!(retrieved_id, block_id);
    }

    #[test]
    fn test_tip() {
        let tmpdir = TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&db_path).unwrap();

        assert!(storage.get_tip().unwrap().is_none());

        let block_id = Hash256::sha256(b"test");
        storage.set_tip(&block_id).unwrap();

        assert_eq!(storage.get_tip().unwrap().unwrap(), block_id);
    }

    #[test]
    fn test_missing_block() {
        let tmpdir = TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&db_path).unwrap();

        let missing = Hash256::sha256(b"nonexistent");
        assert!(storage.get_block(&missing).unwrap().is_none());
    }

    // -------- Phase 3a schema: hand-rolled serializer roundtrips --------

    #[test]
    fn roundtrip_outpoint_key() {
        let op = OutPoint::new(Hash256([0xab; 32]), 0x1234_5678);
        let key = serialize_outpoint_key(&op);
        assert_eq!(key.len(), 36);
        // Little-endian output_index at bytes 32..36.
        assert_eq!(&key[32..36], &0x1234_5678u32.to_le_bytes());
        let parsed = deserialize_outpoint_key(&key).expect("roundtrip");
        assert_eq!(parsed, op);
    }

    #[test]
    fn deserialize_outpoint_key_rejects_wrong_length() {
        assert!(deserialize_outpoint_key(&[0u8; 35]).is_none());
        assert!(deserialize_outpoint_key(&[0u8; 37]).is_none());
        assert!(deserialize_outpoint_key(&[]).is_none());
    }

    #[test]
    fn roundtrip_utxo_entry() {
        let entry = UtxoEntry {
            output: TxOutput::new_p2pkh(7_777_777, &[0xcd; 32]),
            height: 0xdead_beef_cafe,
            is_coinbase: true,
        };
        let bytes = serialize_utxo_entry(&entry).unwrap();
        let parsed = deserialize_utxo_entry(&bytes).expect("roundtrip");
        assert_eq!(parsed.output, entry.output);
        assert_eq!(parsed.height, entry.height);
        assert_eq!(parsed.is_coinbase, entry.is_coinbase);
    }

    #[test]
    fn deserialize_utxo_entry_rejects_trailing_bytes() {
        let entry = UtxoEntry {
            output: TxOutput::new_p2pkh(1, &[1u8; 32]),
            height: 1,
            is_coinbase: false,
        };
        let mut bytes = serialize_utxo_entry(&entry).unwrap();
        bytes.push(0xff); // trailing junk
        assert!(deserialize_utxo_entry(&bytes).is_none());
    }

    #[test]
    fn iter_utxos_empty_on_fresh_db() {
        let tmpdir = TempDir::new().unwrap();
        let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();
        let utxos = storage.iter_utxos().unwrap();
        assert!(utxos.is_empty());
    }

    #[test]
    fn snapshot_tip_none_on_fresh_db() {
        let tmpdir = TempDir::new().unwrap();
        let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();
        assert!(storage.get_utxo_snapshot_tip().unwrap().is_none());
    }

    // -------- Phase 3a behavior: persist + load + idempotency invariants -------

    fn sample_utxo(tag: u8) -> (OutPoint, UtxoEntry) {
        let op = OutPoint::new(Hash256([tag; 32]), tag as u32);
        let entry = UtxoEntry {
            output: TxOutput::new_p2pkh(1_000 + tag as u64, &[tag; 32]),
            height: tag as u64,
            is_coinbase: tag % 2 == 0,
        };
        (op, entry)
    }

    #[test]
    fn finalize_utxo_snapshot_writes_both_markers_atomically() {
        let tmpdir = TempDir::new().unwrap();
        let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();

        let mut set = crate::chain::state::UtxoSet::new();
        let entries: Vec<_> = (1u8..=5).map(sample_utxo).collect();
        for (op, e) in &entries {
            set.insert(*op, e.clone()).unwrap();
        }
        let tip = Hash256([0x77; 32]);

        // Pre-condition: neither marker set, UTXOS_TABLE empty.
        assert!(storage.get_utxo_snapshot_tip().unwrap().is_none());
        assert!(storage.iter_utxos().unwrap().is_empty());

        storage.finalize_utxo_snapshot(&set, &tip).unwrap();

        // Post-condition: marker present AND points at exactly the tip we
        // passed in. Both keys must be set; neither can land in isolation.
        assert_eq!(storage.get_utxo_snapshot_tip().unwrap(), Some(tip));
        let loaded = storage.iter_utxos().unwrap();
        assert_eq!(loaded.len(), entries.len());
        // iter_utxos is key-ordered — check pairwise equality after sorting
        // entries by serialized OutPoint key (matches redb's iteration).
        let mut expected = entries.clone();
        expected.sort_by_key(|(op, _)| serialize_outpoint_key(op));
        for ((lop, le), (eop, ee)) in loaded.iter().zip(expected.iter()) {
            assert_eq!(lop, eop);
            assert_eq!(le, ee);
        }
    }

    #[test]
    fn iter_utxos_byte_stable_across_two_reads() {
        // Pins reviewer's iter-order concern: two open_chain calls on the
        // same datadir must produce the same UTXO sequence, otherwise the
        // SMT rebuild yields different state_roots and the cross-check
        // would falsely flag corruption.
        let tmpdir = TempDir::new().unwrap();
        let path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&path).unwrap();
        let mut set = crate::chain::state::UtxoSet::new();
        for tag in (1u8..=10).rev() {
            // Insert in REVERSE order to verify iter() doesn't reflect
            // insertion order — must reflect key order.
            let (op, e) = sample_utxo(tag);
            set.insert(op, e).unwrap();
        }
        storage
            .finalize_utxo_snapshot(&set, &Hash256([0x55; 32]))
            .unwrap();

        let first = storage.iter_utxos().unwrap();
        let second = storage.iter_utxos().unwrap();
        assert_eq!(first, second);
        // Re-open the database fresh and assert the same sequence is
        // returned — proves the order is on-disk-determined, not
        // process-dependent.
        drop(storage);
        let reopened = ChainStorage::open(&path).unwrap();
        let third = reopened.iter_utxos().unwrap();
        assert_eq!(first, third);
    }

    #[test]
    fn apply_utxo_mutations_intra_block_dependency_order() {
        // Apply order matters: a Remove of outpoint X must be observable
        // even when followed by an Insert of outpoint X within the same
        // mutation log — and the final state must reflect the LAST
        // mutation for any key. Models tx_A creates → tx_B consumes →
        // tx_C re-creates the same OutPoint (legal in principle if
        // tx_A's output had a deterministic id; here we force the
        // pattern explicitly to pin redb's behavior).
        let tmpdir = TempDir::new().unwrap();
        let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();

        let (op, entry_v1) = sample_utxo(3);
        let entry_v2 = UtxoEntry {
            output: TxOutput::new_p2pkh(999_999, &[0xee; 32]),
            height: 99,
            is_coinbase: false,
        };

        let write_txn = storage.db.begin_write().unwrap();
        {
            apply_utxo_mutations(
                &write_txn,
                &[
                    UtxoMutation::Insert(op, entry_v1.clone()),
                    UtxoMutation::Remove(op, entry_v1.clone()),
                    UtxoMutation::Insert(op, entry_v2.clone()),
                ],
            )
            .unwrap();
        }
        write_txn.commit().unwrap();

        let loaded = storage.iter_utxos().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, op);
        assert_eq!(loaded[0].1, entry_v2, "final state reflects last mutation");
    }

    #[test]
    fn commit_block_atomic_writes_utxos_table_in_lockstep() {
        // commit_block_atomic should persist UTXO mutations alongside the
        // block in the SAME write_txn. Verify by writing two blocks with
        // distinct mutation logs and reading UTXOS_TABLE between.
        let tmpdir = TempDir::new().unwrap();
        let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();
        let block = test_block();
        let work = [0u8; 32];

        let (op_a, entry_a) = sample_utxo(1);
        let (op_b, entry_b) = sample_utxo(2);

        storage
            .commit_block_atomic(
                &block,
                &work,
                &[],
                &[
                    UtxoMutation::Insert(op_a, entry_a.clone()),
                    UtxoMutation::Insert(op_b, entry_b.clone()),
                ],
            )
            .unwrap();

        let loaded = storage.iter_utxos().unwrap();
        assert_eq!(loaded.len(), 2);
        let by_op: std::collections::BTreeMap<OutPoint, UtxoEntry> = loaded.into_iter().collect();
        assert_eq!(by_op.get(&op_a), Some(&entry_a));
        assert_eq!(by_op.get(&op_b), Some(&entry_b));

        // Second commit removes op_a, inserts a new op_c. Verifies
        // mutations stack correctly across atomic commits.
        let block2 = {
            let mut b = test_block();
            b.header.height = 1;
            b.header.prev_block_id = block.header.block_id();
            b
        };
        let (op_c, entry_c) = sample_utxo(7);
        storage
            .commit_block_atomic(
                &block2,
                &work,
                &[(op_a, entry_a.clone())],
                &[
                    UtxoMutation::Remove(op_a, entry_a.clone()),
                    UtxoMutation::Insert(op_c, entry_c.clone()),
                ],
            )
            .unwrap();

        let loaded = storage.iter_utxos().unwrap();
        assert_eq!(loaded.len(), 2);
        let by_op: std::collections::BTreeMap<OutPoint, UtxoEntry> = loaded.into_iter().collect();
        assert!(by_op.get(&op_a).is_none(), "op_a removed");
        assert_eq!(by_op.get(&op_b), Some(&entry_b));
        assert_eq!(by_op.get(&op_c), Some(&entry_c));
    }

    #[test]
    fn commit_block_atomic_advances_snapshot_marker_to_new_tip() {
        // Issue #6 reviewer P1: when the snapshot is already complete (the
        // common steady state), every tip advance must move
        // UTXO_SNAPSHOT_TIP_KEY atomically with TIP_KEY. Without this, any
        // block processed between restarts strands the marker on the
        // previous tip and the next `open_chain` logs "snapshot stale" and
        // falls back to a full replay despite UTXOS_TABLE being live.
        let tmpdir = TempDir::new().unwrap();
        let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();
        let work = [0u8; 32];

        // Initialize a complete snapshot via the genesis path. This is the
        // precondition `advance_snapshot_marker_in_txn` requires (it's a
        // no-op when COMPLETE is absent; see the helper's docstring for
        // the legacy-datadir + --no-auto-migrate rationale).
        let genesis = crate::genesis::genesis_block();
        let mut bootstrap_set = crate::chain::state::UtxoSet::new();
        let mut genesis_muts: Vec<UtxoMutation> = Vec::new();
        for tx in &genesis.transactions {
            genesis_muts.extend(bootstrap_set.apply_transaction(tx, 0).unwrap());
        }
        storage
            .commit_genesis_atomic(&genesis, &work, &genesis_muts)
            .unwrap();

        // First non-genesis block: marker advances to its id.
        let block1 = {
            let mut b = test_block();
            b.header.height = 1;
            b.header.prev_block_id = genesis.header.block_id();
            b
        };
        let block1_id = block1.header.block_id();
        let (op_a, entry_a) = sample_utxo(1);
        storage
            .commit_block_atomic(
                &block1,
                &work,
                &[],
                &[UtxoMutation::Insert(op_a, entry_a.clone())],
            )
            .unwrap();
        assert_eq!(
            storage.get_utxo_snapshot_tip().unwrap(),
            Some(block1_id),
            "commit_block_atomic advances the marker when COMPLETE is set"
        );

        // Second block: marker advances again. Without the P1 fix the
        // marker would still point at block1_id here and reopen would log
        // "snapshot stale".
        let block2 = {
            let mut b = test_block();
            b.header.height = 2;
            b.header.prev_block_id = block1_id;
            b
        };
        let block2_id = block2.header.block_id();
        let (op_b, entry_b) = sample_utxo(2);
        storage
            .commit_block_atomic(
                &block2,
                &work,
                &[],
                &[UtxoMutation::Insert(op_b, entry_b.clone())],
            )
            .unwrap();
        assert_eq!(
            storage.get_utxo_snapshot_tip().unwrap(),
            Some(block2_id),
            "second commit_block_atomic advances the marker to the new tip"
        );

        // Marker survives a storage reopen (it's persisted, not cached).
        drop(storage);
        let storage2 = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();
        assert_eq!(
            storage2.get_utxo_snapshot_tip().unwrap(),
            Some(block2_id),
            "marker persists across reopen — open_chain would take the fast path"
        );
    }

    #[test]
    fn commit_block_atomic_does_not_promote_partial_snapshot_to_complete() {
        // Regression for the post-P1 follow-up: a tip update on top of an
        // incomplete snapshot (legacy datadir, post-`clear_utxo_snapshot`,
        // or a `--no-auto-migrate` boot before migration runs) must NOT
        // stamp UTXO_SNAPSHOT_COMPLETE_KEY. Otherwise the next reopen
        // hard-fails into the corruption error path instead of falling
        // back to replay as the `--no-auto-migrate` help text promises.
        let tmpdir = TempDir::new().unwrap();
        let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();
        let work = [0u8; 32];

        // Datadir with chain data but no snapshot markers — same shape as
        // a pre-Phase-3a datadir on its first boot, before any migration.
        let block = test_block();
        let (op, entry) = sample_utxo(0);
        storage
            .commit_block_atomic(
                &block,
                &work,
                &[],
                &[UtxoMutation::Insert(op, entry.clone())],
            )
            .unwrap();
        assert!(
            storage.get_utxo_snapshot_tip().unwrap().is_none(),
            "commit_block_atomic must not promote a partial snapshot to complete"
        );
    }

    #[test]
    fn commit_genesis_atomic_sets_snapshot_marker_to_genesis() {
        // Pair with the commit_block_atomic test: a fresh-datadir bootstrap
        // via commit_genesis_atomic must seed the snapshot marker too. Without
        // this, the very next open after a first-ever boot would fall back
        // to full replay even though UTXOS_TABLE was just populated from the
        // genesis mutation log.
        let tmpdir = TempDir::new().unwrap();
        let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();
        let genesis = crate::genesis::genesis_block();
        let gid = genesis.header.block_id();

        let mut set = crate::chain::state::UtxoSet::new();
        let mut muts: Vec<UtxoMutation> = Vec::new();
        for tx in &genesis.transactions {
            muts.extend(set.apply_transaction(tx, 0).unwrap());
        }
        storage
            .commit_genesis_atomic(&genesis, &[0u8; 32], &muts)
            .unwrap();

        assert_eq!(
            storage.get_utxo_snapshot_tip().unwrap(),
            Some(gid),
            "genesis commit must seed the snapshot marker"
        );
    }

    #[test]
    fn commit_reorg_atomic_does_not_double_open_spent_utxos_table() {
        // Regression guard: pre-fix, commit_reorg_atomic opened
        // SPENT_UTXOS_TABLE twice in one write_txn (once near the top of the
        // function for the new-chain write phase, once again inside the
        // orphan-undo inner block). redb rejects double-open with
        // "Table 'spent_utxos' already opened" — and because the inner-block
        // open runs UNCONDITIONALLY (before the orphan loop body), every
        // single call to commit_reorg_atomic errored, even with empty
        // old_chain_blocks. Surfaced live on `exfer-node-stack` the first
        // time IBD streamed past a fork point after the wedge-fallback fix
        // (PR #13) let the supervisor start IBD at all.
        let tmpdir = TempDir::new().unwrap();
        let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();

        let trigger_block = test_block();
        let work = [1u8; 32];
        let new_tip_id = trigger_block.header.block_id();

        storage
            .commit_reorg_atomic(
                &trigger_block,
                &work,
                /* old_chain_blocks */ &[],
                /* new_chain_spent */ &[],
                /* new_chain_mutations */ &[],
                &[(trigger_block.header.height, new_tip_id)],
                /* new_chain_blocks */ &[],
                /* new_chain_work */ &[],
                /* stale_height_start */ None,
                /* stale_height_end */ None,
                &new_tip_id,
            )
            .expect(
                "commit_reorg_atomic must not double-open SPENT_UTXOS_TABLE in one write_txn",
            );

        assert_eq!(
            storage.get_tip().unwrap(),
            Some(new_tip_id),
            "successful commit must advance TIP_KEY to the trigger block"
        );
    }

    #[test]
    fn commit_reorg_atomic_orphan_undo_reads_spent_table() {
        // Full orphan-undo path: write an orphan block via commit_block_atomic
        // so it has a SPENT_UTXOS_TABLE row, then trigger commit_reorg_atomic
        // with that block in old_chain_blocks. The inner-block read of
        // SPENT_UTXOS_TABLE must succeed and feed the orphan-undo loop —
        // pre-fix this never got that far, because the unconditional second
        // open of SPENT_UTXOS_TABLE inside the same write_txn errored first.
        let tmpdir = TempDir::new().unwrap();
        let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();
        let work = [0u8; 32];

        // Orphan block at height 0 with one consumed UTXO so SPENT_UTXOS_TABLE
        // actually has data for the undo path to load.
        let orphan = test_block();
        let (op_consumed, entry_consumed) = sample_utxo(9);

        storage
            .commit_block_atomic(
                &orphan,
                &work,
                &[(op_consumed, entry_consumed.clone())],
                /* mutations */ &[],
            )
            .unwrap();

        // Reorg trigger at height 1, undoing the orphan.
        let mut trigger = test_block();
        trigger.header.height = 1;
        trigger.header.prev_block_id = orphan.header.prev_block_id;
        trigger.header.nonce = 99;
        let trigger_id = trigger.header.block_id();

        storage
            .commit_reorg_atomic(
                &trigger,
                &[1u8; 32],
                /* old_chain_blocks */ std::slice::from_ref(&orphan),
                /* new_chain_spent */ &[],
                /* new_chain_mutations */ &[],
                &[(trigger.header.height, trigger_id)],
                /* new_chain_blocks */ &[],
                /* new_chain_work */ &[],
                /* stale_height_start */ Some(0),
                /* stale_height_end */ Some(0),
                &trigger_id,
            )
            .expect("orphan-undo path must complete without redb errors");

        assert_eq!(storage.get_tip().unwrap(), Some(trigger_id));

        // The orphan's consumed UTXO must be restored to UTXOS_TABLE — that
        // is the whole point of reading SPENT_UTXOS_TABLE in the undo phase.
        let utxos: std::collections::BTreeMap<OutPoint, UtxoEntry> =
            storage.iter_utxos().unwrap().into_iter().collect();
        assert_eq!(
            utxos.get(&op_consumed),
            Some(&entry_consumed),
            "orphan-undo must restore the spent UTXO from SPENT_UTXOS_TABLE"
        );
    }
}
