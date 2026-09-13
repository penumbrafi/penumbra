//! A migration that prunes extraneous nodes from a Jellyfish Merkle Tree.
//!
//! This migration uses cnidarium's `prune_substore` to stream key-value pairs
//! with range proof verification, then handles pd-specific concerns like
//! directory swapping and substore copying.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cnidarium::{prune_main_substore, PruneConfig, StateDelta, Storage};
use jmt::RootHash;
use penumbra_sdk_app::SUBSTORE_PREFIXES;
use rocksdb::DB;

use super::Migration;

/// Copy all entries from one column family to another, preserving key/value bytes exactly.
fn copy_column_family(old_db: &DB, new_db: &DB, cf_name: &str) -> Result<u64> {
    let old_cf = old_db
        .cf_handle(cf_name)
        .ok_or_else(|| anyhow::anyhow!("column family '{}' not found in old database", cf_name))?;
    let new_cf = new_db
        .cf_handle(cf_name)
        .ok_or_else(|| anyhow::anyhow!("column family '{}' not found in new database", cf_name))?;

    let mut count = 0u64;
    let mut batch = rocksdb::WriteBatch::default();

    let mut iter = old_db.raw_iterator_cf(old_cf);
    iter.seek_to_first();

    while iter.valid() {
        if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
            batch.put_cf(new_cf, key, value);
            count += 1;

            if count % 10_000 == 0 {
                new_db.write(std::mem::take(&mut batch))?;
            }
        }
        iter.next();
    }

    if !batch.is_empty() {
        new_db.write(batch)?;
    }

    Ok(count)
}

/// Operator-facing options for the pruning migration.
#[derive(Debug, Clone)]
pub struct PruneOptions {
    /// Number of key-value pairs per range-proof-verified chunk.
    pub chunk_size: usize,
    /// Delete the unpruned database (`rocksdb_old`) after a successful swap.
    /// Off by default so the operator keeps a rollback until the pruned node
    /// has been verified to sync.
    pub delete_old_db: bool,
}

impl Default for PruneOptions {
    fn default() -> Self {
        Self {
            chunk_size: 100_000,
            delete_old_db: false,
        }
    }
}

/// A state migration that prunes the extraneous nodes from a Jellyfish Merkle Tree.
pub struct JellyfishTreePruner {
    pub options: PruneOptions,
}

/// Refuse to run if the on-disk layout shows a previous run that was interrupted
/// between the two renames of the directory swap, or a kept `rocksdb_old` from a
/// completed run. Both cases hold the operator's only copy of the unpruned state,
/// so the tool must never clean them up on its own.
fn check_directory_layout(rocksdb_dir: &Path, rocksdb_old: &Path, rocksdb_new: &Path) -> Result<()> {
    if rocksdb_old.exists() && !rocksdb_dir.exists() {
        anyhow::bail!(
            "found {} but no {}: a previous prune was interrupted mid-swap. \
             Restore the unpruned database with `mv {} {}` (and remove {} if present) before retrying.",
            rocksdb_old.display(),
            rocksdb_dir.display(),
            rocksdb_old.display(),
            rocksdb_dir.display(),
            rocksdb_new.display(),
        );
    }
    if rocksdb_old.exists() {
        anyhow::bail!(
            "found {} from a previous prune. If the pruned node has been verified, \
             remove it with `rm -rf {}`; otherwise restore it with `mv {} {}`.",
            rocksdb_old.display(),
            rocksdb_old.display(),
            rocksdb_old.display(),
            rocksdb_dir.display(),
        );
    }
    if !rocksdb_dir.exists() {
        anyhow::bail!("no database found at {}", rocksdb_dir.display());
    }
    Ok(())
}

impl Migration for JellyfishTreePruner {
    fn name(&self) -> &'static str {
        "jmt-pruning"
    }

    fn target_app_version(&self) -> Option<u64> {
        // Non-consensus-breaking, no version bump needed
        None
    }

    async fn migrate(
        &self,
        pd_home: &PathBuf,
        _comet_home: Option<&PathBuf>,
    ) -> Result<(RootHash, u64)> {
        let rocksdb_dir = pd_home.join("rocksdb");
        let rocksdb_new = pd_home.join("rocksdb_new");
        let rocksdb_old = pd_home.join("rocksdb_old");

        // Fail closed before touching anything if a previous run left state behind.
        check_directory_layout(&rocksdb_dir, &rocksdb_old, &rocksdb_new)?;

        // Log initial directory size
        let initial_size = dir_size(&rocksdb_dir);
        tracing::info!(initial_size_bytes = initial_size, "rocksdb directory size before pruning");

        let storage = Storage::load(rocksdb_dir.clone(), SUBSTORE_PREFIXES.clone()).await?;
        let snapshot = storage.latest_snapshot();
        let original_root_hash = snapshot.root_hash().await?;
        let version = snapshot.version();

        tracing::info!(?original_root_hash, version, "starting JMT pruning");

        let db = storage.db();

        // A leftover `rocksdb_new` is a partial output from an interrupted run
        // and holds nothing that is not still in `rocksdb`, so it is safe to discard.
        if rocksdb_new.exists() {
            tracing::warn!(path = %rocksdb_new.display(), "removing partial output from a previous run");
            std::fs::remove_dir_all(&rocksdb_new)?;
        }

        // Create destination storage
        tracing::info!("creating fresh database at {:?}", rocksdb_new);
        let new_storage = Storage::load(rocksdb_new.clone(), SUBSTORE_PREFIXES.clone()).await?;
        let new_db = new_storage.db();

        // Configure pruning
        let chunk_size = self.options.chunk_size;
        let prune_config = PruneConfig {
            chunk_size,
            ..Default::default()
        };

        // Prune main store using cnidarium
        tracing::info!(chunk_size, "pruning main store");
        let report = prune_main_substore(
            &storage,
            snapshot,
            &new_storage,
            version,
            &prune_config,
        )?;

        tracing::info!(
            keys_processed = report.keys_processed,
            nodes_before = report.nodes_before,
            nodes_after = report.nodes_after,
            "main store pruned (root hash verified via range proofs)"
        );

        /* **************** copy auxiliary and substore column families **************** */
        tracing::info!("copying auxiliary column families from old database");
        let main_aux_cfs = [
            "config",
            "substore--jmt-keys",
            "substore--jmt-keys-by-keyhash",
            "substore--nonverifiable",
        ];
        for cf_name in main_aux_cfs {
            let count = copy_column_family(&db, &new_db, cf_name)?;
            tracing::info!(cf_name, count, "copied column family");
        }

        /* **************** copy all substores **************** */
        tracing::info!("copying substore column families");
        for prefix in SUBSTORE_PREFIXES.iter() {
            let substore_cfs = [
                format!("substore-{}-jmt", prefix),
                format!("substore-{}-jmt-keys", prefix),
                format!("substore-{}-jmt-values", prefix),
                format!("substore-{}-jmt-keys-by-keyhash", prefix),
                format!("substore-{}-nonverifiable", prefix),
            ];
            for cf_name in substore_cfs {
                let count = copy_column_family(&db, &new_db, &cf_name)?;
                tracing::info!(cf_name, count, "copied column family");
            }
        }

        // Close databases before swap
        drop(new_db);
        drop(db);
        new_storage.release().await;
        storage.release().await;
        tracing::info!("closed both databases");

        // Before the destructive directory swap, reopen the pruned database from
        // scratch and prove it reproduces the original root hash at the original
        // version. cnidarium verifies the streamed tree with range proofs, but
        // the auxiliary column families are copied raw and the config pointer is
        // taken verbatim; a fresh reopen catches any inconsistency (a wrong
        // version pointer surfaces as a version mismatch here) while the original
        // `rocksdb` is still fully intact. On mismatch we bail without swapping.
        {
            let verify = Storage::load(rocksdb_new.clone(), SUBSTORE_PREFIXES.clone())
                .await
                .context("reopening pruned database for verification")?;
            let snapshot = verify.latest_snapshot();
            let new_root_hash = snapshot.root_hash().await?;
            let new_version = snapshot.version();
            verify.release().await;
            anyhow::ensure!(
                new_root_hash == original_root_hash && new_version == version,
                "pruned database verification failed: expected root {:?} at version {}, \
                 got root {:?} at version {}. The original database at {} is untouched; \
                 the bad pruned output is at {} for inspection. Do NOT start pd on it.",
                original_root_hash,
                version,
                new_root_hash,
                new_version,
                rocksdb_dir.display(),
                rocksdb_new.display(),
            );
            tracing::info!(
                ?new_root_hash,
                new_version,
                "verified pruned database reproduces the original root hash"
            );
        }

        // Switch unpruned and pruned databases. Two renames cannot be made atomic
        // together; if we die between them, `check_directory_layout` detects the
        // `rocksdb_old`-without-`rocksdb` layout on the next run and refuses to
        // proceed, and pd's own startup will not find a database to open. Nothing
        // is deleted until both renames have succeeded.
        tracing::info!("swapping database directories");
        std::fs::rename(&rocksdb_dir, &rocksdb_old)
            .with_context(|| format!("renaming {} -> {}", rocksdb_dir.display(), rocksdb_old.display()))?;
        if let Err(e) = std::fs::rename(&rocksdb_new, &rocksdb_dir) {
            // Roll the first rename back so the node is left exactly as we found it.
            tracing::error!(error = %e, "second rename failed, restoring unpruned database");
            std::fs::rename(&rocksdb_old, &rocksdb_dir)
                .with_context(|| format!("rollback of {} -> {} failed; restore it manually", rocksdb_old.display(), rocksdb_dir.display()))?;
            return Err(e).with_context(|| format!("renaming {} -> {}", rocksdb_new.display(), rocksdb_dir.display()));
        }

        // fsync the parent directory so the rename pair is durable across a power
        // loss, not only a process kill. Best-effort: a failure here does not
        // undo the successful swap, so warn rather than abort.
        match std::fs::File::open(pd_home) {
            Ok(dir) => {
                if let Err(e) = dir.sync_all() {
                    tracing::warn!(error = %e, "could not fsync pd home after swap");
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not open pd home to fsync after swap"),
        }

        if self.options.delete_old_db {
            tracing::info!("removing old database");
            std::fs::remove_dir_all(&rocksdb_old)?;
        } else {
            tracing::info!(
                path = %rocksdb_old.display(),
                size_bytes = initial_size,
                "kept unpruned database for rollback; remove it once the pruned node is verified"
            );
        }

        // Clean up LOG.old files
        for entry in std::fs::read_dir(&rocksdb_dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("LOG.old") {
                    std::fs::remove_file(entry.path())?;
                }
            }
        }

        let final_size = dir_size(&rocksdb_dir);
        let saved = initial_size.saturating_sub(final_size);
        tracing::info!(
            "pruning complete: {} {:.1} GB ({:.1} GB -> {:.1} GB)",
            if self.options.delete_old_db {
                "saved"
            } else {
                "will save, once rocksdb_old is removed,"
            },
            saved as f64 / 1e9,
            initial_size as f64 / 1e9,
            final_size as f64 / 1e9,
        );

        Ok((original_root_hash, version))
    }

    async fn migrate_inner(&self, _delta: &mut StateDelta<cnidarium::Snapshot>) -> Result<()> {
        Ok(())
    }

    async fn complete(
        &self,
        _pd_home: &PathBuf,
        _comet_home: Option<&PathBuf>,
        _post_upgrade_root_hash: jmt::RootHash,
        _post_upgrade_height: u64,
        _genesis_start: Option<tendermint::time::Time>,
    ) -> Result<()> {
        Ok(())
    }
}

/// Helper to calculate directory size recursively.
fn dir_size(path: &Path) -> u64 {
    let mut size = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                size += dir_size(&path);
            } else if let Ok(meta) = path.metadata() {
                size += meta.len();
            }
        }
    }
    size
}
