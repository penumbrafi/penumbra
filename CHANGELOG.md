# Changelog

## 2.1.2

**This is the coordinated RESTART release for `penumbra-1`.** It is
consensus-breaking. Every node on the network, validator or not, must run the
migration in this release to follow the chain. `APP_VERSION` becomes 12.

Penumbra is community-maintained; Rotko Networks coordinates releases, published from
`rotkonetworks/penumbra`.

### What happened

`penumbra-1` stopped producing blocks after height **12,598,600**, last block
time **2026-09-02T19:37:07Z**. Validators holding more than one third of the
voting power went offline (iqlusion, 30.0%, and Tessellated, 3.7%), so no
block could reach a two-thirds precommit. The application state is intact,
and every node that reached the halt reports the same state root:

```
last_block_height  12598600
last_block_app_hash  6fd4f811f8e1fcc2c67d7ea2ccc75cef228acc2b9a738b8514c9e163c5cd859a
                     (base64: b9T4Efjh/MLGfX6izMdc7yKKzCuac4uFFMnhY8XNhZo=)
```

### What the restart does

`pd migrate --force restart-mainnet-1` is a new, fully self-contained
migration. Every parameter that affects the result is compiled into the
binary. It:

1. Marks iqlusion and Tessellated **`Disabled`**, exactly as if their operators
   had uploaded a definition with `enabled = false`. Their delegation pools
   start unbonding. The remaining 14 validators then hold 100% of the voting
   power. Either validator can come back later by uploading a new definition
   with `enabled = true`.
2. Executes an **empty application block 12,598,601** through the same code
   path `pd` uses for every block, with a fixed header (time
   `2026-09-02T19:37:12Z`). This keeps the application state and the compact
   block stream contiguous, so wallets keep syncing without changes.
3. Writes a new checkpoint genesis with **`initial_height` 12,598,602** and the
   compiled-in **`genesis_time` `2026-09-08T12:00:00Z`**. CometBFT will not
   propose before that instant; the chain resumes when validators holding two
   thirds of the new voting power are online.
4. Bumps the app version to 12. This release is otherwise the upstream 2.1.1
   code, so the restart doubles as the 2.1 upgrade.

Why 12,598,602 and not 12,598,601: every validator that was online at the
halt already signed votes for height 12,598,601 on the halted chain.
CometBFT's double-sign protection will not let it sign those rounds again, and
a chain restarted at that height can never advance. Restarting one height
later sidesteps this entirely, and no vote from the halted chain can ever be
used as evidence against a validator on the restarted chain. **There is no
CometBFT block 12,598,601.** Block explorers and reindexers will see a gap of
one block; application state and compact blocks are continuous. Likewise, the
validator state change events for iqlusion and Tessellated were emitted inside
the migration and appear in no block: indexers will see two delegation pools
start unbonding without a corresponding event.

### Post-restart validator set

| Validator | Share of voting power |
|---|---|
| rotko.net | 27.83% |
| polkachu.com | 22.37% |
| antumbra.net | 11.17% |
| ghostinnet | 7.39% |
| CryptoCrew Validators | 6.05% |
| Bryanlabs | 5.63% |
| silent | 5.48% |
| Architect Nodes | 5.07% |
| MathNodes | 2.73% |
| Pro-Delegators | 1.78% |
| AM Solutions | 1.34% |
| OriginStake | 1.06% |
| Validatus | 1.06% |
| PathrockNetwork | 1.04% |

Two thirds of the new set is reached, for example, with rotko.net, polkachu.com,
antumbra.net and ghostinnet plus any one more validator. The chain waits until
that much power is online.

### Expected results

Every operator produces exactly the same state and genesis. Compare these
values before starting your node. If any of them differ, stop and ask in the
validator channel; do not start.

```
pre-migration root hash   6fd4f811f8e1fcc2c67d7ea2ccc75cef228acc2b9a738b8514c9e163c5cd859a
post-migration root hash  cae7229981ed712e85fa0c7596ff4302d214b4f7167a42ea0f665fe4e90822e0
genesis.json sha256       d93600d5cbc6c8b6d173178fb14b5a679430e2b1f9721eea601f6b45737e4506
genesis initial_height    12598602
genesis_time              2026-09-08T12:00:00Z
pd version                2.1.2
```

### Step by step for validators

Read everything once before starting. The migration itself takes well under a
minute (31 seconds on a 322 GB unpruned store, on NVMe); most of the time goes
into the backup. Nodes may be migrated at any time
before the genesis time. Once migrated, a node can be started immediately: it
will wait for the genesis time on its own.

**Do not migrate a live validator until you have rehearsed on a copy**, or at
least have a complete backup of the `pd` home you can restore. The migration
rewrites the `pd` database in place and deletes CometBFT's block store.

1. **Stop both services.** CometBFT first, then `pd`.
   ```sh
   sudo systemctl stop cometbft
   sudo systemctl stop penumbra
   ```
2. **Verify you are at the halt height with the expected state.** With
   CometBFT stopped, look at the last lines of its log, or, before stopping
   it, run:
   ```sh
   curl -s localhost:26657/abci_info
   ```
   `last_block_height` must be `12598600` and `last_block_app_hash` must be
   `b9T4Efjh/MLGfX6izMdc7yKKzCuac4uFFMnhY8XNhZo=`. If your node never
   reached 12,598,600, restore the halt-height snapshot (see below) first.
3. **Back up.** Copy the whole node directory, or take a filesystem snapshot.
   The `pd` home is the directory that contains `rocksdb`; the CometBFT home
   contains `config` and `data`. **Never delete or hand-edit
   `config/priv_validator_key.json` or `data/priv_validator_state.json`.** The
   migration raises the signing state to the new height itself.
   ```sh
   cp -a /path/to/node0 /path/to/node0.pre-restart
   ```
   If you have little disk, the halt-height snapshot published by Rotko is
   byte-for-byte the same state and can serve as your backup instead.
4. **Install `pd` 2.1.2** from this release and check it:
   ```sh
   pd --version      # pd 2.1.2
   ```
   The release page lists the sha256 of every binary.
5. **Run the migration** as the user that owns the node directory, with a
   raised open-file limit. Pass both homes explicitly. `--force` is required
   because the chain was never halted by governance; the migration still
   refuses to run on any height other than 12,598,600 or on any other state
   root.
   ```sh
   sudo -u penumbra bash -c 'ulimit -n 65536; \
     pd migrate --force \
       --home /path/to/node0/pd \
       --comet-home /path/to/node0/cometbft \
       restart-mainnet-1'
   ```
6. **Compare the output with the expected results above.** The log contains,
   in this order:
   ```
   starting migration pre_upgrade_root_hash=RootHash("6fd4f811…")
   validator removed from consensus name=iqlusion …
   validator removed from consensus name=Tessellated …
   rewrote the consensus keys reported to CometBFT before=16 after=14
   post-restart active set validators=14 total_power=4701138836800
   empty block 12598601 committed
   post-migration root hash post_upgrade_root_hash=RootHash("cae7229981ed712e85fa0c7596ff4302d214b4f7167a42ea0f665fe4e90822e0")
   successful migration! … post_upgrade_height=12598602
   ```
   Then check the genesis file the migration wrote into your CometBFT home:
   ```sh
   sha256sum /path/to/node0/cometbft/config/genesis.json   # d93600d5cbc6c8b6d173178fb14b5a679430e2b1f9721eea601f6b45737e4506
   cat /path/to/node0/cometbft/data/priv_validator_state.json
   ```
   `priv_validator_state.json` must show `"height": "12598602"`, round 0,
   step 0.
7. **Start `pd`, then CometBFT.**
   ```sh
   sudo systemctl start penumbra
   sudo systemctl start cometbft
   ```
   CometBFT logs `Genesis time is in the future. Sleeping until then` and
   does nothing until the genesis time. Leave it running.
8. **After the genesis time**, confirm the node is signing:
   ```sh
   curl -s localhost:26657/status | jq .result.sync_info
   ```
   `latest_block_height` climbs from 12,598,602. Block 12,598,602 carries
   `app_hash` `cae7229981ed712e85fa0c7596ff4302d214b4f7167a42ea0f665fe4e90822e0` in its header. If two thirds of the new
   voting power is not yet online, the log shows repeated round timeouts at
   height 12,598,602; that is expected until enough validators join.

### If something goes wrong

- **The migration refused to run** (wrong height or root hash): your state is
  not the network's state at the halt. Restore from the halt-height snapshot
  and run the migration again.
- **The migration failed half way**: restore your backup (or the halt-height
  snapshot) and run it again. Do not start `pd` on a half-migrated database.
- **You started the node and it is on a different genesis** (its
  `genesis.json` sha256 differs, or it cannot find peers at 12,598,602): stop
  both services, restore the backup, and redo steps 4 to 7 with the binary
  from this release. Do not touch `priv_validator_state.json`.
- **Never lower `priv_validator_state.json` by hand**, on any chain, for any
  reason.

### Snapshots

Both are published at <https://snapshot.rotko.net/> as direct downloads and
torrents, with sha256 manifests.

- **Halt-height snapshot, 12,598,600 (pre-restart).** The exact state the
  migration expects. Use it to restore a node that did not reach the halt, or
  as the backup to redo a failed migration. Its `pd` database is JMT-pruned;
  the migration accepts pruned and unpruned databases alike and produces the
  same result (verified: identical root hashes on a pruned 24 GB store and on
  an unpruned 322 GB copy of a mainnet validator).
- **Post-restart snapshot** (published once the chain is producing blocks
  again). New nodes join from this one.

### Non-validator nodes (RPC, archive, relayers)

Run exactly the same steps. `priv_validator_state.json` is irrelevant for
you, and `--comet-home` is still required so the new genesis is written.
Archive operators: take a copy of your CometBFT `data` directory before
running the migration if you want to keep the pre-restart block history; the
migration deletes the block store.

### IBC

Light clients of `penumbra-1` on counterparty chains have most likely expired
during the halt (trusting periods are shorter than the halt). Those need the
usual client recovery on each counterparty. Nothing in this release changes
IBC state on Penumbra.

### Everything else

This release is the upstream `v2.1.1` code plus the restart migration, a
`pmonitor` dependency fix, and CI on GitHub-hosted runners. `pd migrate prune`
from 2.0.8 is not in this release; it lands in the next 2.1.x release.
