# Changelog

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
