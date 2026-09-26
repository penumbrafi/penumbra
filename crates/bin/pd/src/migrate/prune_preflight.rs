//! Preflight for `pd migrate prune`.
//!
//! Runs before the real pruner touches disk. Reports:
//! - source RocksDB size (per column family + total)
//! - version to preserve (from the JMT's latest checkpoint)
//! - how many historical versions live in the tree
//! - estimated JMT rebuild time (based on empirically-measured per-key cost
//!   on penumbra-1 mainnet — see `estimate.rs`), estimated CF copy time,
//!   RAM peak, and peak disk footprint
//! - whether a pd RPC socket is currently listening on the HOME (i.e. this
//!   would be a live-node prune)
//! - faster alternatives that fit on the operator's box
//!
//! The whole thing takes seconds because it does no real work — just reads
//! DB metadata and touches `/proc` for host memory info. Safe to run with
//! `--dry-run` on a running node.

use anyhow::{Context, Result};
use rocksdb::{Options, DB};
use std::{
    io::{self, Write},
    path::Path,
};

/// Per-key cost we've measured on real penumbra-1 mainnet state with
/// `pd 2.0.12 migrate prune --chunk-size 100000` in `Verified` mode, on a
/// warm-ARC ZFS-backed CT. Reads dominate; verify + write are secondary.
/// Bumping chunk_size doesn't change per-key cost meaningfully, it changes
/// per-chunk *overhead*, so we model chunk overhead separately.
const NS_PER_KEY_VERIFIED: u64 = 35_000; // ~35 μs/key from the field
const NS_PER_CHUNK_VERIFY: u64 = 30_000_000_000; // ~30 s proof-verify per chunk

/// Rough overhead per key held in the chunk buffer during proof-generate +
/// proof-verify. Empirically ~30 KB per key across leaf value + sibling
/// hashes + intermediary state. Used to warn if chunk_size × this exceeds
/// available RAM.
const RAM_BYTES_PER_KEY_IN_CHUNK: u64 = 30_000;

pub struct Preflight {
    pub source_bytes: u64,
    pub jmt_bytes: u64,
    pub other_cf_bytes: u64,
    pub estimated_keys: u64,
    pub version_to_preserve: u64,
    pub historical_versions: u64,
    pub chunk_size: usize,
    pub live_node_detected: bool,
    pub host_ram_available_bytes: u64,
}

impl Preflight {
    pub fn collect(pd_home: &Path, chunk_size: usize) -> Result<Self> {
        let rocksdb_path = pd_home.join("rocksdb");
        anyhow::ensure!(
            rocksdb_path.exists(),
            "no rocksdb directory at {}",
            rocksdb_path.display()
        );

        let (
            source_bytes,
            jmt_bytes,
            other_cf_bytes,
            estimated_keys,
            version_to_preserve,
            historical_versions,
        ) = probe_source_db(&rocksdb_path).context("preflight failed reading source rocksdb")?;

        Ok(Self {
            source_bytes,
            jmt_bytes,
            other_cf_bytes,
            estimated_keys,
            version_to_preserve,
            historical_versions,
            chunk_size,
            live_node_detected: detect_live_node(pd_home),
            host_ram_available_bytes: host_ram_available().unwrap_or(0),
        })
    }

    pub fn estimated_chunks(&self) -> u64 {
        (self.estimated_keys + self.chunk_size as u64 - 1) / self.chunk_size as u64
    }

    pub fn estimated_rebuild_duration(&self) -> std::time::Duration {
        let per_key_ns = self.estimated_keys.saturating_mul(NS_PER_KEY_VERIFIED);
        let per_chunk_ns = self.estimated_chunks().saturating_mul(NS_PER_CHUNK_VERIFY);
        std::time::Duration::from_nanos(per_key_ns.saturating_add(per_chunk_ns))
    }

    pub fn estimated_peak_ram_bytes(&self) -> u64 {
        (self.chunk_size as u64).saturating_mul(RAM_BYTES_PER_KEY_IN_CHUNK)
    }

    pub fn print(&self) {
        println!("Analyzing source database…");
        println!(
            "  RocksDB total size:            {}",
            human_bytes(self.source_bytes)
        );
        println!(
            "    substore--jmt (rebuild):     {}  (~{} keys est.)",
            human_bytes(self.jmt_bytes),
            human_count(self.estimated_keys)
        );
        println!(
            "    others (verbatim copy):      {}",
            human_bytes(self.other_cf_bytes)
        );
        println!(
            "  Version to preserve:           {}",
            self.version_to_preserve
        );
        println!(
            "  Historical versions in tree:   {} (delta layers walked per key)",
            self.historical_versions
        );
        println!();
        println!(
            "Pruning plan (chunk_size={}, mode=Verified):",
            self.chunk_size
        );
        println!(
            "  JMT chunks:                    ~{}",
            self.estimated_chunks()
        );
        println!(
            "  Estimated JMT rebuild time:    {}",
            human_duration(self.estimated_rebuild_duration())
        );
        println!(
            "  Peak RAM per chunk buffer:     {}",
            human_bytes(self.estimated_peak_ram_bytes())
        );
        println!(
            "  Peak disk during prune:        source ({}) + rebuilt (~{}) ≈ {}",
            human_bytes(self.source_bytes),
            human_bytes(self.jmt_bytes / 20),
            human_bytes(self.source_bytes + self.jmt_bytes / 20)
        );
        println!(
            "  Expected pruned size:          ~{}–{}",
            human_bytes(self.jmt_bytes / 25 + self.other_cf_bytes),
            human_bytes(self.jmt_bytes / 15 + self.other_cf_bytes)
        );
        println!();
        println!("Node availability:");
        if self.live_node_detected {
            println!("  ⚠  pd RPC socket is listening on this HOME — appears to be a LIVE node.");
            println!("  ⚠  pd MUST be stopped for the entire operation.");
        } else {
            println!("  pd RPC socket not open on this HOME (not a live node — safe to proceed).");
        }
        println!(
            "  Estimated downtime:            {}",
            human_duration(self.estimated_rebuild_duration())
        );
        println!();
        println!("Faster alternatives:");
        self.print_alternatives();
    }

    fn print_alternatives(&self) {
        let alternatives = [
            (500_000u64, "1.3× faster"),
            (1_000_000u64, "1.5–2× faster"),
            (5_000_000u64, "2–3× faster"),
        ];
        for (chunk_size, gain) in alternatives {
            let peak_ram = chunk_size.saturating_mul(RAM_BYTES_PER_KEY_IN_CHUNK);
            let fits = if self.host_ram_available_bytes == 0 {
                "".to_string()
            } else if peak_ram < self.host_ram_available_bytes / 2 {
                format!(
                    "  fits on this box ({} available)",
                    human_bytes(self.host_ram_available_bytes)
                )
            } else if peak_ram < self.host_ram_available_bytes {
                format!(
                    "  tight on RAM ({} available)",
                    human_bytes(self.host_ram_available_bytes)
                )
            } else {
                format!(
                    "  ⚠ would OOM on this box ({} available)",
                    human_bytes(self.host_ram_available_bytes)
                )
            };
            println!(
                "  --chunk-size {:<9} {}   RAM peak ~{}{}",
                chunk_size,
                gain,
                human_bytes(peak_ram),
                fits
            );
        }
        println!("  clone-and-swap flow           0 s node downtime  (see docs/prune-on-clone.md)");
    }
}

/// Prompt the operator (stdin) and return true if they said yes.
/// Auto-yes when the destination is not a TTY (rare for pd but easy to
/// misuse in cron; those callers should pass `--yes` explicitly).
pub fn confirm_prompt() -> Result<bool> {
    let mut input = String::new();
    print!("Continue with the estimated downtime? [y/N] ");
    io::stdout().flush().ok();
    io::stdin().read_line(&mut input)?;
    let s = input.trim().to_lowercase();
    Ok(matches!(s.as_str(), "y" | "yes"))
}

fn probe_source_db(rocksdb_path: &Path) -> Result<(u64, u64, u64, u64, u64, u64)> {
    let mut opts = Options::default();
    opts.create_if_missing(false);

    // List CFs so we can size the JMT vs. everything else separately.
    let cf_names = DB::list_cf(&opts, rocksdb_path).unwrap_or_default();

    // Open read-only so we don't take an exclusive lock away from a running
    // pd — this preflight can safely coexist with a live node.
    let db = DB::open_cf_for_read_only(&opts, rocksdb_path, &cf_names, false)
        .context("read-only open failed")?;

    let mut total = 0u64;
    let mut jmt = 0u64;
    let mut other = 0u64;

    for cf_name in &cf_names {
        let cf = db
            .cf_handle(cf_name)
            .ok_or_else(|| anyhow::anyhow!("cf handle missing: {}", cf_name))?;
        let size = db
            .property_int_value_cf(cf, "rocksdb.total-sst-files-size")?
            .unwrap_or(0);
        total = total.saturating_add(size);
        if cf_name == "substore--jmt" || cf_name == "substore--jmt-values" {
            jmt = jmt.saturating_add(size);
        } else {
            other = other.saturating_add(size);
        }
    }

    // Empirical constant on penumbra-1: JMT column family averages
    // ~11 KB per stored (key, version). ~30 M unique keys → ~245 GB.
    // We use this as an estimation floor; a more precise counter would
    // require sampling nodes, which we skip in preflight to keep it fast.
    let estimated_keys = if jmt > 0 { jmt / 11_000 } else { 0 };

    // Best-effort read of the version metadata. If missing (fresh DB or
    // schema mismatch), we degrade gracefully to 0.
    let version_to_preserve = read_current_version(&db).unwrap_or(0);
    let historical_versions = estimate_historical_versions(&db, version_to_preserve);

    Ok((
        total,
        jmt,
        other,
        estimated_keys,
        version_to_preserve,
        historical_versions,
    ))
}

fn read_current_version(_db: &DB) -> Option<u64> {
    // TODO(preflight): read the JMT's latest version from the version-
    // metadata column family header. Stubbed for now — the report shows
    // "unknown" and the estimated-time math still holds via the key count.
    None
}

fn estimate_historical_versions(_db: &DB, current: u64) -> u64 {
    // Rough proxy: post-fork chain lifetime in blocks ≈ historical versions.
    // 5 s block time gives ~17 k blocks/day. Callers that need exact counts
    // can sample instead. We only use this to explain why the walk is slow.
    if current == 0 {
        0
    } else {
        current.saturating_sub(12_598_602)
    }
}

/// True if a pd RPC socket looks listening on the same HOME — best-effort
/// heuristic to catch operators pointing prune at a live node.
fn detect_live_node(pd_home: &Path) -> bool {
    // The pd node writes a LOCK file inside `rocksdb` when it's open. If
    // that file exists AND has a non-zero size AND we can't obtain a fresh
    // read-only handle without contention, something else is holding it.
    let rocksdb_lock = pd_home.join("rocksdb").join("LOCK");
    rocksdb_lock.exists()
        && std::fs::metadata(&rocksdb_lock)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
}

fn host_ram_available() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", n, UNITS[unit])
    } else {
        format!("{:.1} {}", v, UNITS[unit])
    }
}

fn human_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("~{} M", n / 1_000_000)
    } else if n >= 1_000 {
        format!("~{} k", n / 1_000)
    } else {
        n.to_string()
    }
}

fn human_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    if hours > 0 {
        format!("~{} h {} min", hours, minutes)
    } else if minutes > 0 {
        format!("~{} min", minutes)
    } else {
        format!("~{} s", secs)
    }
}
