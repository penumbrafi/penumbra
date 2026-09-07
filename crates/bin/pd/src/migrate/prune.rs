//! Offline pruning of the main-store Jellyfish Merkle Tree.
//!
//! Rebuilds the main JMT at its latest version into a fresh database using
//! cnidarium's range-proof-verified streaming, copies every other column family
//! unchanged, verifies the copy, then swaps the new database into place.
//! Local-only and non-consensus-breaking: the root hash is unchanged, and so is
//! every value the node reads.
//!
//! Two things have to hold for the swapped-in database to be usable, and both
//! are checked before anything is renamed:
//!
//! * the rebuilt JMT hashes to the same root -- covered by the per-chunk range
//!   proofs inside cnidarium, and re-checked by reopening the pruned database;
//! * everything the pruner did not rebuild survives byte for byte -- covered by
//!   fingerprinting every other column family in both databases.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cnidarium::{
    copy_column_families, prune_main_substore, verify_column_families, PruneConfig, Storage,
};
use jmt::RootHash;
use penumbra_sdk_app::SUBSTORE_PREFIXES;
use rocksdb::{Options, DB};

/// The only column families the pruner rebuilds. Every other column family in
/// the database -- including ones added after this was written -- is copied
/// across verbatim and then verified.
const REBUILT_COLUMN_FAMILIES: [&str; 2] = ["substore--jmt", "substore--jmt-values"];

/// Operator-facing options for pruning.
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

/// Refuse to run if the on-disk layout shows a previous run that was interrupted
/// between the two renames of the directory swap, or a kept `rocksdb_old` from a
/// completed run. Both hold the operator's only copy of the unpruned state, so
/// the tool must never clean them up on its own.
fn check_directory_layout(
    rocksdb_dir: &Path,
    rocksdb_old: &Path,
    rocksdb_new: &Path,
) -> Result<()> {
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

/// Prune the pd database under `pd_home`. Returns the (unchanged) root hash and version.
pub async fn prune(pd_home: &PathBuf, options: &PruneOptions) -> Result<(RootHash, u64)> {
    let rocksdb_dir = pd_home.join("rocksdb");
    let rocksdb_new = pd_home.join("rocksdb_new");
    let rocksdb_old = pd_home.join("rocksdb_old");

    // Fail closed before touching anything if a previous run left state behind.
    check_directory_layout(&rocksdb_dir, &rocksdb_old, &rocksdb_new)?;

    let initial_size = dir_size(&rocksdb_dir);
    tracing::info!(
        initial_size_bytes = initial_size,
        "rocksdb directory size before pruning"
    );

    // Take the column family list from the database itself, so a column family
    // this code does not know about cannot be silently dropped.
    let cf_names = DB::list_cf(
        &Options::default(),
        rocksdb_dir.to_str().context("rocksdb path is not utf-8")?,
    )
    .context("listing column families")?;
    tracing::info!(column_families = ?cf_names, "found column families");

    let storage = Storage::load(rocksdb_dir.clone(), SUBSTORE_PREFIXES.to_vec()).await?;
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

    tracing::info!("creating fresh database at {:?}", rocksdb_new);
    let new_storage = Storage::load(rocksdb_new.clone(), SUBSTORE_PREFIXES.to_vec()).await?;
    let new_db = new_storage.db();

    let chunk_size = options.chunk_size;
    let prune_config = PruneConfig {
        chunk_size,
        ..Default::default()
    };
    tracing::info!(chunk_size, "pruning main store");
    let report = prune_main_substore(&storage, snapshot, &new_storage, version, &prune_config)?;
    tracing::info!(
        keys_processed = report.keys_processed,
        nodes_before = report.nodes_before,
        nodes_after = report.nodes_after,
        "main store pruned (root hash verified via range proofs)"
    );

    if !report.value_overrides.is_empty() {
        // The source database's JMT commits to a different value than its value
        // column family returns for these keys. The pruned database reproduces
        // both, so the node keeps its app hash *and* reads what the rest of the
        // network reads, but the operator should know the store carries them.
        tracing::warn!(
            count = report.value_overrides.len(),
            "the source database's merkle tree and value column family disagree on some keys; \
             the pruned database preserves the source's read values"
        );
        for (key_hash, value) in report.value_overrides.iter() {
            tracing::warn!(
                key_hash = %hex::encode(key_hash.0),
                read_value = ?value.as_ref().map(hex::encode),
                "preserved read-path value"
            );
        }
    }

    tracing::info!("copying every column family the pruner did not rebuild");
    let rebuilt: Vec<String> = REBUILT_COLUMN_FAMILIES.iter().map(|s| s.to_string()).collect();
    let copied = copy_column_families(&db, &new_db, &cf_names, &rebuilt)?;
    tracing::info!(
        column_families = copied.len(),
        entries = copied.iter().map(|(_, n)| n).sum::<u64>(),
        "copied column families"
    );

    // Nothing above this point verifies the copy: the range proofs only cover
    // the rebuilt JMT. Compare every copied column family in both databases and
    // refuse to swap on any difference -- `rocksdb_old` is the operator's only
    // copy of the unpruned state.
    tracing::info!("verifying copied column families");
    verify_column_families(&db, &new_db, &cf_names, &rebuilt)
        .context("pruned database failed column family verification; nothing was swapped")?;

    drop(new_db);
    drop(db);
    new_storage.release().await;
    storage.release().await;
    tracing::info!("closed both databases");

    // Reopen the pruned database on its own and confirm it comes up at the same
    // version and root hash the source reported.
    {
        let check = Storage::load(rocksdb_new.clone(), SUBSTORE_PREFIXES.to_vec()).await?;
        let snapshot = check.latest_snapshot();
        let new_version = snapshot.version();
        let new_root = snapshot.root_hash().await?;
        drop(snapshot);
        check.release().await;
        anyhow::ensure!(
            new_version == version && new_root == original_root_hash,
            "pruned database reopened at version {new_version} root {new_root:?}, \
             expected version {version} root {original_root_hash:?}; nothing was swapped",
        );
        tracing::info!(?new_root, new_version, "pruned database verified on reopen");
    }

    // Two renames cannot be made atomic together; if we die between them,
    // `check_directory_layout` and pd's own startup detect the layout and
    // refuse to proceed. Nothing is deleted until both renames have succeeded.
    tracing::info!("swapping database directories");
    std::fs::rename(&rocksdb_dir, &rocksdb_old).with_context(|| {
        format!(
            "renaming {} -> {}",
            rocksdb_dir.display(),
            rocksdb_old.display()
        )
    })?;
    if let Err(e) = std::fs::rename(&rocksdb_new, &rocksdb_dir) {
        tracing::error!(error = %e, "second rename failed, restoring unpruned database");
        std::fs::rename(&rocksdb_old, &rocksdb_dir).with_context(|| {
            format!(
                "rollback of {} -> {} failed; restore it manually",
                rocksdb_old.display(),
                rocksdb_dir.display()
            )
        })?;
        return Err(e).with_context(|| {
            format!(
                "renaming {} -> {}",
                rocksdb_new.display(),
                rocksdb_dir.display()
            )
        });
    }

    if options.delete_old_db {
        tracing::info!("removing old database");
        std::fs::remove_dir_all(&rocksdb_old)?;
    } else {
        tracing::info!(
            path = %rocksdb_old.display(),
            size_bytes = initial_size,
            "kept unpruned database for rollback; remove it once the pruned node is verified"
        );
    }

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
        if options.delete_old_db {
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
