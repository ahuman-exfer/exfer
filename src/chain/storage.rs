use crate::chain::state::UtxoEntry;
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
const TIP_KEY: &str = "tip_block_id";

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
    pub fn commit_genesis_atomic(
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

            let mut height_idx = write_txn.open_table(HEIGHT_INDEX)?;
            height_idx.insert(block.header.height, block_id.as_bytes().as_ref())?;

            let mut work = write_txn.open_table(WORK_TABLE)?;
            work.insert(block_id.as_bytes().as_ref(), cumulative_work.as_ref())?;

            let mut meta = write_txn.open_table(META_TABLE)?;
            meta.insert(TIP_KEY, block_id.as_bytes().as_ref())?;

            // Index genesis transaction IDs
            let mut tx_idx = write_txn.open_table(TX_INDEX_TABLE)?;
            for tx in &block.transactions {
                if let Ok(tid) = tx.tx_id() {
                    tx_idx.insert(tid.as_bytes().as_ref(), block.header.height)?;
                }
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Atomically commit a new canonical block (extends-tip path).
    /// Performs store_block + cumulative_work + spent_utxos + canonical_height + tip
    /// in a single redb write transaction for crash consistency.
    pub fn commit_block_atomic(
        &self,
        block: &Block,
        cumulative_work: &[u8; 32],
        spent_utxos: &[(OutPoint, UtxoEntry)],
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
    #[allow(clippy::too_many_arguments)]
    pub fn commit_reorg_atomic(
        &self,
        trigger_block: &Block,
        cumulative_work: &[u8; 32],
        new_chain_spent: &[(Hash256, Vec<(OutPoint, UtxoEntry)>)],
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
}
