# Storage pruning and network bootstrap policy

Maintained by the Penumbra community. Last revised 2026-09-09.

## Where the disk goes

A mainnet full node measured in September 2026, about 12 million blocks:

| Store | Size | Contents | Affects bootstrap of new nodes? |
|---|---|---|---|
| pd main JMT (`substore--jmt`, `--jmt-values`) | ~315 GB | every historical version of the Merkle tree | no |
| pd history substores (`cometbft-data`, compact blocks, nonverifiable) | ~3 GB | per-height transactions and compact blocks, served over RPC to wallets | no, but wallets need them |
| CometBFT blockstore + state + tx index | ~65 GB | every block since genesis | **yes** |

A new node joins by replaying every block from genesis through its own pd. It
fetches blocks from peers' CometBFT blockstores. It never fetches pd state from
peers, because pd does not implement ABCI state sync (`ListSnapshots` returns
an empty list).

## Rules

1. **`pd migrate prune` is an opt-in tool, not a policy.** It collapses the
   main JMT to a single version and leaves history substores and CometBFT
   untouched, so it does not affect network bootstrap and needs no
   coordination. It exists for validator operators who want smaller disks.
   It is not something every node should run, and nobody is asked to run it.

   Several operators, including some of the largest validators, keep their
   nodes fully unpruned on purpose; between them they are the network's
   archive. Shipping the tool is not a recommendation to use it.

2. **CometBFT block retention stays disabled in pd until state sync exists.**
   pd returns `retain_height = 0` from `Commit`, so no node can prune its
   blockstore. If every node pruned blocks, no new node could ever join. Do not
   add a retention flag before pd can serve and restore verified state
   snapshots over the ABCI snapshot protocol. When that lands, the retention
   floor must be computed from the chain's evidence parameters at runtime and
   pd must refuse lower values.

3. **RPC and archive nodes stay unpruned.** Historical state-tree versions are
   what IBC relayers (proofs at recent heights) and explorers (state at a
   height) query. At least one public RPC endpoint must stay fully unpruned as
   the archive and relayer target. A node that is pruned regrows its history from the
   prune point onward, so the gap is temporary, but an archive should not have
   one. Independently of that, **RPC operators never prune history substores.** Wallets scan compact
   blocks from their birthday forward. Pruning them breaks user sync, which is
   worse than a validator failing to join.

4. **The core validator set keeps full history.** With a validator set of a
   handful of nodes, erasure coding or sharding history is pointless.
   Replication across all core validators is the archive. A validator that
   chooses to prune gives up the ability to answer historical queries — state
   at a past height, proofs at a past height — for everything before its prune
   point. That is a fine trade for a pure block-producer and an unacceptable
   one for anything an explorer, relayer or wallet points at.

## Upgrades destroy block history; the reindexer archive is the real history

At a consensus upgrade, `pd migrate` writes a new genesis whose
`initial_height` is the upgrade height and then deletes CometBFT's data
directory, blockstore included, on every node. After an upgrade no node holds
any block from the previous era. "Keep all blocks" therefore only ever means
"all blocks since the last upgrade", and the permanent history of the chain is
the sequence of `penumbra-reindexer` archives, one per era.

Rules:

1. Run `penumbra-reindexer archive` continuously against an unpruned node so
   the current era is captured as it grows.
2. Before any upgrade, and before anyone runs `pd migrate`, finalize and
   publish the archive for the ending era, keep a copy of the pre-upgrade `pd`
   data directory, and publish the post-upgrade `pd` state snapshot that new
   nodes need to join a chain whose genesis starts mid-history.

## Cost of this policy

A JMT-pruned node carries about 90 GB instead of about 380 GB, and CometBFT
grows around 30 GB per year. The remaining 65 GB is the price of a network
that can always bootstrap itself. Revisit rule 2 once state sync ships.

## Running it

Ships in **pd 2.0.11** (= pd 2.0.9 + this tool). Drop-in, not
consensus-breaking, `APP_VERSION` unchanged at 11.

**Use 2.0.11, not 2.0.10.** On a store taken after the 12598601 restart, the
2.0.10 pruner produced a database with the correct root hash that `pd start`
could not use; see "When the tree and the value store disagree" below.

It is not an upgrade migration: the network is never halted for it, there is no
prune height, and nodes may prune at different versions. Each node rebuilds its
own tree at whatever version it is sitting at and the root hash comes out
identical, so pruned and unpruned nodes are indistinguishable to consensus.
The only cost is that *your* node is offline while it runs.

### Procedure

1. Install the 2.0.11 binary. No migration is needed to adopt it.
2. Make sure there is free disk for the pruned copy, about 10% of the current
   store (35 GB for mainnet). The unpruned database is kept until you delete
   it, so both exist for a while.
3. Stop **both** services. CometBFT exits when its ABCI connection to `pd` goes
   away and would otherwise crash-loop for the duration.
   ```sh
   systemctl stop cometbft penumbra
   ```
4. Run as the user that owns the `pd` data directory, with a raised open-file
   limit. `--home` is the directory that contains `rocksdb`; always pass it.
   ```sh
   sudo -u penumbra bash -c 'ulimit -n 1048576 && pd migrate --home <pd_home> prune'
   ```
5. Start `pd` first, then CometBFT.
   ```sh
   systemctl start penumbra && systemctl start cometbft
   ```
6. The unpruned database is kept at `<pd_home>/rocksdb_old`. Delete it once the
   node has followed the chain for a day. A second prune refuses to run while
   it exists; `pd start` runs normally with it present.

Flags: `--chunk-size N` (default 100000) trades memory for proof work;
`--delete-old-db` removes `rocksdb_old` automatically instead of keeping it,
which is not recommended for a first run.

### The open-file limit is the most common failure

The default soft limit of 1024 is far too low — a mainnet prune holds several
thousand descriptors open (7,675 measured) — and rocksdb fails partway through,
not at startup. Note the `&&`: if `ulimit` cannot raise the limit, the prune
must not run at all. An unprivileged user cannot exceed the hard limit, so on
`Operation not permitted` use `ulimit -n $(ulimit -Hn)` or raise `LimitNOFILE`
in the unit file. Anything above about 16384 is enough.

### When the tree and the value store disagree

`pd migrate-restart` in 2.0.9 committed the migration in place and then built
the synthetic block from a snapshot taken before that write, so three keys on
`penumbra-1` came out of the 12598601 restart with a merkle leaf committing to
the pre-migration value while the value column family holds the migrated one.
Nodes read the value column family; the app hash follows the tree.

The 2.0.10 pruner replayed the tree, which silently replaced those read values
— on mainnet it turned a Disabled validator Active again and crashed `pd` on
the first block after the swap. From 2.0.11 the pruner records every key where
the two paths disagree and rewrites the value row with what the read path
returned, leaving the tree and hence the root hash untouched. Each one is
logged as `preserved read-path value`, with a summary warning naming the count;
seeing them on a post-restart store is expected, not a fault.

cnidarium 0.83.2 fixes the cause: `commit_in_place` now refreshes the snapshot
cache, so a future in-place migration cannot leave the same divergence behind.

### Verifying the result

The log ends with `JMT pruning complete root_hash=...`. That hash must equal
the one printed at the start in `starting JMT pruning`. If it does not, do not
start the node: restore `rocksdb_old` and report it.

Before the directory swap, 2.0.11 also fingerprints (entry count and a rolling
SHA-256) every column family it did not rebuild in both databases and reopens
the pruned store to confirm it comes up at the same version and root hash. Any
mismatch aborts the run with both directories untouched.

### Cost and timing

Measured on a copy of mainnet state at version 12,561,008: 350 GB to 30 GB in
59 minutes on one core, 4.7 GB peak resident, 64.7 million keys, root hash
unchanged. On a host sharing its NVMe pool with other live nodes the same work
runs roughly four times slower. Budget hours rather than an hour. The run is
safe to leave unattended and safe to interrupt.

Downtime jailing is not the concern: the uptime window is 10,000 blocks with a
maximum of 9,500 missed, so even a multi-hour prune is far from the threshold.
Check `pcli query validator uptime` for your identity first anyway.

### Operational rules

* One validator at a time. Never take more than a third of voting power
  offline at once.
* Not within 24 hours of the 12598602 restart unless the node is not a
  validator.
* RPC, archive, indexer and snapshot-provider nodes do not prune (rule 3
  above). Never prune with a version older than 2.0.11.
* `rocksdb_old` is kept; delete it only after the node has followed the chain
  for a day.

## Recovery from an interrupted prune

`pd migrate prune` keeps the unpruned store at `rocksdb_old` by default and
refuses to run or start if it finds an inconsistent layout. Follow the
instructions in the error message; they name the exact `mv` to run.
