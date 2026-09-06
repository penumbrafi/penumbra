# Storage pruning and network bootstrap policy

Maintained by Rotko Networks. Decided 2026-09-06.

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

1. **`pd migrate prune` is safe for every node and does not affect bootstrap.**
   It collapses the main JMT to a single version and leaves history substores
   and CometBFT untouched. Run it on every validator and RPC node.

2. **CometBFT block retention stays disabled in pd until state sync exists.**
   pd returns `retain_height = 0` from `Commit`, so no node can prune its
   blockstore. If every node pruned blocks, no new node could ever join. Do not
   add a retention flag before pd can serve and restore verified state
   snapshots over the ABCI snapshot protocol. When that lands, the retention
   floor must be computed from the chain's evidence parameters at runtime and
   pd must refuse lower values.

3. **RPC operators never prune history substores.** Wallets scan compact
   blocks from their birthday forward. Pruning them breaks user sync, which is
   worse than a validator failing to join.

4. **The core validator set keeps full history.** With a validator set of a
   handful of nodes, erasure coding or sharding history is pointless.
   Replication across all core validators is the archive.

## Cost of this policy

A JMT-pruned node carries about 90 GB instead of about 380 GB, and CometBFT
grows around 30 GB per year. The remaining 65 GB is the price of a network
that can always bootstrap itself. Revisit rule 2 once state sync ships.

## Recovery from an interrupted prune

`pd migrate prune` keeps the unpruned store at `rocksdb_old` by default and
refuses to run or start if it finds an inconsistent layout. Follow the
instructions in the error message; they name the exact `mv` to run.
