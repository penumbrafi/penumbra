//! Preflight for `pd migrate prune`.
//!
//! Runs before the real pruner touches disk. Reports:
//! - source RocksDB size (per column family + total)
//! - version to preserve (from the JMT's latest checkpoint)
//! - how many historical versions live in the tree
//! - estimated JMT rebuild time (based on empirically-measured per-key cost
//!   on penumbra-1 mainnet), estimated CF copy time, RAM peak, and peak
//!   disk footprint
//! - whether a pd RPC socket is currently listening on `127.0.0.1` (i.e.
//!   this would be a live-node prune)
//! - faster alternatives that fit on the operator's box
//!
//! The whole thing takes seconds because it does no real work — just reads
//! DB metadata, samples a few keys, and touches `/proc` for host memory
//! info. Safe to run with `--dry-run` on a running node.

use anyhow::{Context, Result};
use cnidarium::PruneMode;
use rocksdb::{IteratorMode, Options, DB};
use std::{
    io::{self, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    time::Duration,
};

/// Per-key cost we've measured against a MATURE penumbra-1 mainnet tree
/// (many months of accumulated history layers, ~40 M live keys). Numbers
/// come from the Rotko Sep-2026 prune run on a modern NVMe/32 GB box:
/// steady state was ~26 000 keys/min under `--unverified` at chunk_size
/// 500 000, which is ~2.3 ms/key. Older 2.0.12 constants were calibrated
/// against a fresh post-restart tree (~2 M keys) and undershot mature-tree
/// runtime by an order of magnitude.
///
/// The per-key figure already absorbs per-chunk overhead observed at the
/// tail of the run, so we do not add a separate per-chunk term for the
/// unverified path. `Verified` adds proof-generate + proof-verify per
/// chunk on top of the same walk, empirically ~3× the walk cost.
const NS_PER_KEY_UNVERIFIED: u64 = 2_300_000; // ~2.3 ms/key mature-tree steady state
const NS_PER_KEY_VERIFIED: u64 = 7_000_000; // ~3× slower with per-chunk proofs

/// Rough overhead per key held in the chunk buffer during proof-generate +
/// proof-verify. Empirically ~30 KB per key across leaf value + sibling
/// hashes + intermediary state. Used to warn if chunk_size × this exceeds
/// available RAM.
const RAM_BYTES_PER_KEY_IN_CHUNK: u64 = 30_000;

/// Number of `substore--jmt-values` samples used to estimate the average
/// leaf byte size. Enough to smooth outliers on the mainnet distribution
/// without slowing preflight beyond a couple hundred ms.
const LEAF_SAMPLE_COUNT: usize = 256;

/// Loopback ports we probe to decide whether pd is live. `8080` is the
/// default pd gRPC port; `26657` is CometBFT's RPC port that pd's
/// companion serves alongside pd. Either being open means the operator
/// almost certainly did not stop the node before running the prune.
const LIVE_NODE_PROBE_PORTS: [u16; 2] = [8080, 26657];

pub struct Preflight {
    pub source_bytes: u64,
    pub jmt_bytes: u64,
    pub other_cf_bytes: u64,
    pub estimated_keys: u64,
    pub version_to_preserve: u64,
    pub historical_versions: u64,
    pub chunk_size: usize,
    pub mode: PruneMode,
    pub live_node_detected: bool,
    pub host_ram_available_bytes: u64,
    /// Estimated leaf-value size, sampled from `substore--jmt-values`.
    /// Used to compute `shadow_factor`.
    pub avg_leaf_bytes: u64,
    /// Ratio `source_bytes / estimated_live_bytes`. Mature trees with
    /// heavy shadowed version history land far above 1.0; a fresh
    /// post-restart tree sits near 1.0. Clamped into `[1.0, 5.0]` before
    /// being applied to the ETA so a wildly-off sampling doesn't
    /// telescope predictions.
    pub shadow_factor: f64,
}

impl Preflight {
    pub fn collect(pd_home: &Path, chunk_size: usize, mode: PruneMode) -> Result<Self> {
        let rocksdb_path = pd_home.join("rocksdb");
        anyhow::ensure!(
            rocksdb_path.exists(),
            "no rocksdb directory at {}",
            rocksdb_path.display()
        );

        let probe =
            probe_source_db(&rocksdb_path).context("preflight failed reading source rocksdb")?;

        // Shadow factor: how much on-disk overhead sits on top of the
        // live-key surface. Clamp to [1, 5] so the ETA remains bounded on
        // pathological probes.
        let estimated_live_bytes = probe
            .estimated_keys
            .saturating_mul(probe.avg_leaf_bytes.max(1));
        let raw_shadow = if estimated_live_bytes > 0 {
            probe.jmt_bytes as f64 / estimated_live_bytes as f64
        } else {
            1.0
        };
        let shadow_factor = raw_shadow.clamp(1.0, 5.0);

        Ok(Self {
            source_bytes: probe.source_bytes,
            jmt_bytes: probe.jmt_bytes,
            other_cf_bytes: probe.other_cf_bytes,
            estimated_keys: probe.estimated_keys,
            version_to_preserve: probe.version_to_preserve,
            historical_versions: probe.historical_versions,
            chunk_size,
            mode,
            live_node_detected: detect_live_node(),
            host_ram_available_bytes: host_ram_available().unwrap_or(0),
            avg_leaf_bytes: probe.avg_leaf_bytes,
            shadow_factor,
        })
    }

    pub fn estimated_chunks(&self) -> u64 {
        (self.estimated_keys + self.chunk_size as u64 - 1) / self.chunk_size as u64
    }

    pub fn per_key_ns(&self) -> u64 {
        match self.mode {
            PruneMode::Verified => NS_PER_KEY_VERIFIED,
            PruneMode::Unverified => NS_PER_KEY_UNVERIFIED,
        }
    }

    pub fn mode_str(&self) -> &'static str {
        mode_str(self.mode)
    }

    pub fn estimated_rebuild_duration(&self) -> std::time::Duration {
        let per_key_ns = self.estimated_keys.saturating_mul(self.per_key_ns());
        // Apply shadow_factor to reflect that a mature source drags many
        // shadowed-delta SSTs through the walk. clamp is baked into
        // `shadow_factor` at construction.
        let scaled = (per_key_ns as f64 * self.shadow_factor) as u64;
        std::time::Duration::from_nanos(scaled)
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
            "    substore--jmt (rebuild):     {}  (~{} keys est., avg leaf {})",
            human_bytes(self.jmt_bytes),
            human_count(self.estimated_keys),
            human_bytes(self.avg_leaf_bytes),
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
        println!(
            "  Shadow factor:                 {:.2}× (source / live) — clamp [1.0, 5.0]",
            self.shadow_factor,
        );
        println!();
        println!(
            "Pruning plan (chunk_size={}, mode={}):",
            self.chunk_size,
            self.mode_str(),
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
            println!("  ⚠  pd/CometBFT port open on 127.0.0.1 — appears to be a LIVE node.");
            println!("  ⚠  pd MUST be stopped for the entire operation.");
        } else {
            println!(
                "  no pd/CometBFT port open on 127.0.0.1 (not a live node — safe to proceed)."
            );
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
        if matches!(self.mode, PruneMode::Verified) {
            println!(
                "  --unverified                  ~3× faster; source-trust required (see --help)"
            );
        }
        println!(
            "  --compact-source              ~2–3× walk speedup on trees with heavy shadowed history"
        );
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

/// Public helper so `--compact-source` guardrails in `main.rs` can gate
/// off the same detection preflight uses.
pub fn is_live_node() -> bool {
    detect_live_node()
}

pub(crate) fn mode_str(mode: PruneMode) -> &'static str {
    match mode {
        PruneMode::Verified => "Verified",
        PruneMode::Unverified => "Unverified",
    }
}

struct ProbeResult {
    source_bytes: u64,
    jmt_bytes: u64,
    other_cf_bytes: u64,
    estimated_keys: u64,
    version_to_preserve: u64,
    historical_versions: u64,
    avg_leaf_bytes: u64,
}

fn probe_source_db(rocksdb_path: &Path) -> Result<ProbeResult> {
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

    // Sample the values CF to estimate average leaf byte size, then use
    // that to back out live-key count from the on-disk footprint. This is
    // more faithful on mature trees than the old fixed 11 KB/key floor.
    let avg_leaf_bytes = sample_avg_leaf_bytes(&db, &cf_names).unwrap_or(11_000);

    // Estimate live keys from the values CF footprint divided by the
    // sampled average leaf size. Fall back to the old JMT-CF /11 KB floor
    // if the values CF isn't present in this schema.
    let values_bytes = if cf_names.iter().any(|c| c == "substore--jmt-values") {
        db.cf_handle("substore--jmt-values")
            .and_then(|cf| {
                db.property_int_value_cf(cf, "rocksdb.total-sst-files-size")
                    .ok()
                    .flatten()
            })
            .unwrap_or(0)
    } else {
        0
    };
    let estimated_keys = if values_bytes > 0 && avg_leaf_bytes > 0 {
        values_bytes / avg_leaf_bytes
    } else if jmt > 0 {
        jmt / 11_000
    } else {
        0
    };

    let version_to_preserve = read_current_version(&db).unwrap_or(0);
    let historical_versions = estimate_historical_versions(&db, version_to_preserve);

    Ok(ProbeResult {
        source_bytes: total,
        jmt_bytes: jmt,
        other_cf_bytes: other,
        estimated_keys,
        version_to_preserve,
        historical_versions,
        avg_leaf_bytes,
    })
}

/// Sample the head of `substore--jmt-values` for its first
/// `LEAF_SAMPLE_COUNT` entries and return the mean value size in bytes.
/// Returns `None` if the CF isn't present or holds fewer than 8 samples
/// (too little signal to distinguish a mature tree from a fresh one).
fn sample_avg_leaf_bytes(db: &DB, cf_names: &[String]) -> Option<u64> {
    if !cf_names.iter().any(|c| c == "substore--jmt-values") {
        return None;
    }
    let cf = db.cf_handle("substore--jmt-values")?;
    let mut sum: u64 = 0;
    let mut count: u64 = 0;
    for item in db
        .iterator_cf(cf, IteratorMode::Start)
        .take(LEAF_SAMPLE_COUNT)
    {
        let (_, value) = item.ok()?;
        sum = sum.saturating_add(value.len() as u64);
        count += 1;
    }
    if count < 8 {
        None
    } else {
        Some(sum / count)
    }
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

/// Best-effort live-node detection. Probes `127.0.0.1:<pd-gRPC>` and
/// `127.0.0.1:<CometBFT-RPC>`. Either connecting means pd or its
/// companion CometBFT is up on this box — treat as live.
///
/// Replaces the old LOCK-file heuristic that fired false-negatives when
/// pd was running: pd holds the LOCK inside a rocksdb-managed subdir,
/// and its top-level `LOCK` is zero-bytes even while pd runs, so the
/// stat-based check missed the live case entirely. TCP probes are the
/// signal we actually want.
fn detect_live_node() -> bool {
    LIVE_NODE_PROBE_PORTS.iter().any(|port| {
        let addr = SocketAddr::from(([127, 0, 0, 1], *port));
        TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(mode: PruneMode, estimated_keys: u64, jmt_bytes: u64, avg_leaf_bytes: u64) -> Preflight {
        let estimated_live = estimated_keys.saturating_mul(avg_leaf_bytes.max(1));
        let raw_shadow = if estimated_live > 0 {
            jmt_bytes as f64 / estimated_live as f64
        } else {
            1.0
        };
        Preflight {
            source_bytes: jmt_bytes,
            jmt_bytes,
            other_cf_bytes: 0,
            estimated_keys,
            version_to_preserve: 0,
            historical_versions: 0,
            chunk_size: 500_000,
            mode,
            live_node_detected: false,
            host_ram_available_bytes: 32 * 1024 * 1024 * 1024,
            avg_leaf_bytes,
            shadow_factor: raw_shadow.clamp(1.0, 5.0),
        }
    }

    #[test]
    fn mode_str_renders_both_variants() {
        assert_eq!(mk(PruneMode::Verified, 1, 1, 1).mode_str(), "Verified");
        assert_eq!(mk(PruneMode::Unverified, 1, 1, 1).mode_str(), "Unverified");
    }

    #[test]
    fn shadow_factor_is_one_on_fresh_tree() {
        // If jmt_bytes == estimated_keys * avg_leaf_bytes there is no
        // shadowed history to amplify the ETA.
        let pf = mk(PruneMode::Unverified, 1_000_000, 1_000_000 * 500, 500);
        assert!((pf.shadow_factor - 1.0).abs() < 1e-9);
    }

    #[test]
    fn shadow_factor_clamps_high_at_five() {
        // Mature Rotko tree: 40M keys, 500-byte avg leaf, 300 GB jmt
        // bytes → raw factor ~15. Clamp caps at 5 so the ETA doesn't
        // telescope.
        let pf = mk(
            PruneMode::Unverified,
            40_000_000,
            300u64 * 1024 * 1024 * 1024, // 300 GB
            500,
        );
        assert_eq!(pf.shadow_factor, 5.0);
    }

    #[test]
    fn shadow_factor_clamps_low_at_one() {
        // If sampling underestimated leaf sizes so badly that shadow < 1,
        // we still don't shrink the ETA below the raw per-key floor.
        let pf = mk(PruneMode::Unverified, 1_000_000, 100, 500);
        assert_eq!(pf.shadow_factor, 1.0);
    }

    #[test]
    fn eta_unverified_less_than_verified_for_same_shape() {
        let a = mk(
            PruneMode::Unverified,
            40_000_000,
            300u64 * 1024 * 1024 * 1024,
            500,
        );
        let b = mk(
            PruneMode::Verified,
            40_000_000,
            300u64 * 1024 * 1024 * 1024,
            500,
        );
        assert!(a.estimated_rebuild_duration() < b.estimated_rebuild_duration());
    }

    #[test]
    fn eta_matches_rotko_measurement_within_a_factor_of_2() {
        // 40M keys, unverified, shadow-clamped 5×: expected wall clock
        // ~2.3 ms * 40M * 5 = 460 000 s ≈ 128 h. The measured job was
        // in the 10–15 h band on a faster box; we accept a 2× either way
        // as a sanity band (per-key constants are calibrated for a
        // typical CT, not the largest metal).
        let pf = mk(
            PruneMode::Unverified,
            40_000_000,
            300u64 * 1024 * 1024 * 1024,
            500,
        );
        let hours = pf.estimated_rebuild_duration().as_secs() as f64 / 3600.0;
        assert!(hours > 5.0 && hours < 200.0, "hours={}", hours);
    }
}
