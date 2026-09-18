# Changelog

## 2.0.14 (unreleased)

More operator ergonomics for `pd migrate prune`. No consensus change;
drop-in for a running 2.0.13 node. Motivated by the Rotko Sep-2026
mainnet prune, which sat at ~26 000 keys/min for 15+ hours on a mature
40 M-key tree while the 2.0.13 preflight kept reporting a 50-minute ETA.

- Preflight recalibration. The per-key cost constants are now measured
  against a mature-tree run (~2.3 ms/key `--unverified` steady state,
  ~7 ms/key `Verified`), not a fresh post-restart tree. Preflight also
  computes a **shadow factor** — the ratio of on-disk footprint to
  estimated live-key surface — by sampling `substore--jmt-values` for
  the average leaf size and dividing the CF footprint. Clamped to
  `[1.0, 5.0]` and applied to the ETA, so mature-tree reports land in
  the 8–12 h band instead of the 50 min band. The mature-tree measurement
  used chunk_size 500 000 on modern NVMe/32 GB metal.
- Preflight now reflects the mode selected on the CLI. Previously
  `--unverified` was decoded in `main.rs` after preflight ran, so the
  report always printed `mode=Verified`. `Preflight::collect` now takes
  `PruneMode` and prints the right label. Per-key ETA also picks the
  right constant off the mode.
- Live-node detection rewritten. The old LOCK-file heuristic returned
  false-negatives while pd was running (pd writes a zero-byte top-level
  `LOCK` and keeps its real lock inside a rocksdb-managed subdir). We
  now probe TCP `127.0.0.1:8080` (pd gRPC) and `127.0.0.1:26657`
  (CometBFT RPC) — either connecting flags the node as live.
- New `--compact-source` flag. Before the pruner opens the source for
  the walk, run RocksDB `compact_range` on every column family in place.
  Collapses shadowed version-delta SSTs so the walk iterator hits fewer,
  larger, coalesced files; empirical 2–3× walk speedup on trees with
  heavy shadowed history. Off by default. Refuses to run if the
  live-node probe fires — compacting an open RocksDB corrupts the tree.
  Requires the paired `--i-understand-source-compaction-modifies-source`
  confirmation flag (mirrors the `--unverified` pattern): compaction
  rewrites SSTs, so an interrupted prune leaves the source no longer
  bit-identical to its pre-run state.

## 2.0.13

Operator ergonomics for `pd migrate prune`. No consensus change; drop-in for
a running 2.0.12 node.

- `pd migrate prune` gains a preflight report that runs before any files are
  written to `rocksdb_new`. Prints source RocksDB size, estimated JMT keys,
  estimated wall-clock rebuild time (based on empirically-measured per-key
  and per-chunk costs on penumbra-1 mainnet), peak RAM per chunk buffer,
  peak disk footprint, expected pruned size, whether the pd RPC socket is
  currently listening on the same HOME (best-effort live-node detection),
  and a table of faster alternatives filtered by `/proc/meminfo`
  MemAvailable so we don't recommend a chunk-size that would OOM.
- New `--dry-run` flag prints the preflight report and exits 0 without
  touching disk. Safe on a running node — the source RocksDB is opened
  read-only.
- New `--yes` / `-y` flag bypasses the confirmation prompt for
  automation. Without it, a detected live node OR an estimated downtime
  greater than 1 h requires an explicit `y` before the prune starts.
  Motivated by the Rotko `penumbra.rotko.net` incident where an 11 h
  live-RPC prune had to be aborted because the operator's mental model
  was a ~1 h prune done previously on a scratch dataset under 2.0.8.
- New `--unverified` flag turns on `PruneMode::Unverified` from
  cnidarium. Skips per-chunk range-proof generation and verification;
  still checks the rebuilt root hash matches the source's original root
  at the end of each substore. About 3× faster on penumbra-1
  mainnet-scale JMTs (from ~15 h to ~5 h in `Verified` mode).
- `--unverified` requires the paired flag
  `--i-understand-this-drops-per-chunk-verification` to actually take
  effect, so operators can't trip into unverified mode by mistake.
  Strongly recommend taking a filesystem snapshot (ZFS, btrfs, LVM)
  before running with this flag.
- Internal: `restart_fork.rs` renamed to `mainnet5_community_fork.rs`
  to fit the `mainnet<N>.rs` convention used for every prior on-chain
  migration in this directory. `restart-fork:` tracing message prefixes
  preserved so operator archives from the actual Sep 2026 restart stay
  grep-able. Public `pd::migrate::mainnet5_community_fork::run` is the
  new call path — callers that referenced `pd::migrate::restart_fork::`
  need to update the module path.

Requires `cnidarium` 0.83.3 (added `PruneMode::Unverified`).

## 2.0.11

pd 2.0.11 is pd 2.0.10 with a fixed `pd migrate prune`. Same consensus code,
`APP_VERSION` still 11, same restart genesis: a drop-in for a running 2.0.9 or
2.0.10 node, with no migration, no upgrade height and no coordination.
`git diff v2.0.10..v2.0.11 -- crates/core` is empty. Do not re-run
`migrate-restart` from pre-restart state to join the chain — the `commit_in_place`
fix below changes what it produces; join from a post-restart snapshot.

**2.0.10's `pd migrate prune` must not be run on post-restart state.** It
produced a database with the correct root hash that `pd start` could not use.

### What changed

* Pruning detects any key where the merkle leaf and the value store disagree —
  the restart migration left three of them on `penumbra-1` — and preserves the
  value a node reads, leaving the tree and the root hash untouched. Every such
  key is logged.
* Every column family the pruner does not rebuild is fingerprinted in both
  databases, and the pruned store reopened at the same version and root hash,
  before any directory is renamed. A mismatch aborts, swapping nothing.
* `cnidarium` 0.83.2 (tag `v0.83.2`) carries the other half: `commit_in_place`
  now refreshes the snapshot cache, which is what left the divergence behind.

### Pruning

Stop **both** cometbft and pd, then run as the `pd` user with a raised limit:
`sudo -u penumbra bash -c 'ulimit -n 1048576 && pd migrate --home <pd_home> prune'`.
Budget 1–4 hours and ~5 GB RAM for a full store; start pd first, then cometbft.
`<pd_home>/rocksdb_old` keeps the unpruned copy — delete it after a day of
following the chain. One validator at a time; archive, RPC, indexer and
snapshot-provider nodes do not prune, and never with an older version.
Full procedure: [`docs/pruning.md`](https://github.com/penumbrafi/penumbra/blob/v2.0.11/docs/pruning.md).

### Assets

`pd`, `pcli`, `pclientd`, `pindexer`, `pmonitor` and `elcuity` for linux x86_64
and aarch64; reproduce with `cargo build --release --locked`.

Maintained by the Penumbra community — <https://github.com/penumbrafi/penumbra>.

## 2.0.10

pd 2.0.10 is pd 2.0.9 plus one new command, `pd migrate prune`. Same consensus
code, `APP_VERSION` still 11, same `migrate-restart` and same restart genesis.
Drop-in: 2.0.9 and 2.0.10 nodes run side by side, and adopting it needs no
migration, no upgrade height and no coordination. The only diff outside
`crates/bin/pd` is a comment — check with
`git diff v2.0.9..v2.0.10 -- crates/core`.

### `pd migrate prune`

Offline pruning of the state store: collapses the historical versions of the
Jellyfish Merkle Tree to the latest one, verifying every key against the
unchanged root hash with range proofs as it rebuilds. On mainnet this takes the
`pd` database from roughly 350 GB to roughly 30 GB.

It is **not** an upgrade migration: no network halt, no prune height, and nodes
may prune at different versions. The root hash is unchanged, so pruned and
unpruned nodes are indistinguishable to consensus. The only cost is your own
node being offline while it runs — an hour on a quiet NVMe host, several on a
busy one.

```sh
systemctl stop cometbft penumbra
sudo -u penumbra bash -c 'ulimit -n 1048576 && pd migrate --home <pd_home> prune'
systemctl start penumbra && systemctl start cometbft
```

1. **Stop both `pd` and CometBFT.** CometBFT crash-loops without its ABCI peer.
2. **One validator at a time**, never more than a third of voting power offline
   at once, and not within 24 hours of the restart.
3. **Archive, RPC and indexer nodes do not prune.** A pruned node cannot answer
   queries about state before its prune point, which breaks relayers and
   explorers. The network needs unpruned nodes to exist.

The unpruned database is kept at `<pd_home>/rocksdb_old`; delete it once the
node has followed the chain for a day. Full procedure, failure modes and the
open-file-limit trap: [`docs/pruning.md`](docs/pruning.md).

### Assets

Linux x86_64 and aarch64, built by GitHub Actions from this tag; reproduce with
`cargo build --release --locked`. Verify downloads against `SHA256SUMS`.
`cnidarium` is pinned to `penumbrafi/cnidarium` 0.83.1 (`e37da88`) for the
verified pruning API; no existing storage or proof code path is modified.

Maintained by the Penumbra community —
<https://github.com/penumbrafi/penumbra>.

## 2.0.9

The penumbra-1 coordinated restart release. See `restart/`.
