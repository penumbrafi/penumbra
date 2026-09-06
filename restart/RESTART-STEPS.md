# penumbra-1 coordinated restart — validator runbook

penumbra-1 halted at height **12598600**. This restart continues the **same
chain-id** (`penumbra-1`) — all balances and delegations preserved — by disabling
the two departed validators (iqlusion, polkachu) and keeping the other 14. Every
kept validator can rejoin.

## Key values (verify against these)

| | |
|---|---|
| restart height (genesis `initial_height`) | `12598602` (the migration executes an empty app block 12598601 itself) |
| genesis sha256 | `c099ccb02a2136d5071fb22b1511eeec1588ad09676e0a0532d072f28b433ed4` |
| app_hash / post_root | `1db72ab20c0babdb8696f361d5b08d790abd8032ac64d762b138ddc80f0f99f7` |
| removed (disabled, no penalty) | iqlusion `3969C0511C6ABE474757FEAB7C1B4004796D7E72`, polkachu `9B2D4391131198750FF28EE73EC953ECFCFD06EF` |
| go-window | **SET BY COORDINATORS** (before the noble client expiry `2026-09-07 11:37 UTC`) |

**The one hard rule:** fully stop your old halted node before starting the
migrated one. Running the old and new node on the same key = double-sign =
permanent tombstone.

**Verify, don't trust:** your own `pd migrate-restart` must reproduce the exact
genesis sha256 above. That hash — not any prebuilt binary — is the cross-check.

## Why the restart height is 12598602, not 12598601

Every validator that was online at the halt already signed votes for height
12598601 (rounds 0–2) on the halted chain. CometBFT's double-sign protection
refuses to sign those rounds again, and a round only advances on two-thirds of
votes, so a chain restarted at 12598601 sits at height 0 forever. This was
reproduced on a copy of the real halt state. Resetting `priv_validator_state`
is not an answer: the halted chain's votes are public and carry the same
chain-id, so a fresh vote at the same height and round could be turned into
double-sign evidence.

`pd migrate-restart` therefore executes an **empty application block 12598601**
itself (same code path as every block, fixed header) and writes the genesis at
**12598602**. Your signing state is raised to 12598602 by the migration; no
hand-editing. Application state and compact blocks stay contiguous, so wallets
keep syncing. There is simply no CometBFT block 12598601 — explorers will see a
one-block gap.

---

## 0. Get the binary

Download `pd` **v2.0.9** (Linux x86_64; on arm64 build from source) — it includes `migrate-restart`
and is what the revived chain runs. Earlier builds (2.0.6 branch builds, v2.0.8)
restart at 12598601 and **cannot start the chain**; do not use them.
<https://github.com/penumbrafi/penumbra/releases/tag/v2.0.9>

```sh
# example, x86_64:
curl -fsSL -o pd.tar.gz https://github.com/penumbrafi/penumbra/releases/download/v2.0.9/pd-recovery-2.0.9-x86_64-linux-gnu.tar.gz
tar xzf pd.tar.gz && sudo install pd-recovery-2.0.9-x86_64-linux-gnu/pd /usr/local/bin/pd
sha256sum /usr/local/bin/pd   # compare with SHA256SUMS on the release page
pd --version    # -> pd 2.0.9
```

Or build from source (see
[`restart/README.md`](https://github.com/penumbrafi/penumbra/blob/restart/penumbra-1-12598601/restart/README.md)).
Either way `pd migrate-restart` must reproduce the genesis sha above.

Reference genesis (539 bytes, sha `c099ccb0…`) for comparison is attached to the
v2.0.9 release and lives at `restart/candidate-genesis-penumbra-1-restart-12598602-disable.json`.

---

## A. Existing validator (you ran penumbra-1 before the halt)

You have your halted node dir with `pd/` (rocksdb) and `cometbft/`. Adjust the
paths below to your layout.

### The easy path
[`restart/penumbra-restart.sh`](https://github.com/penumbrafi/penumbra/blob/restart/penumbra-1-12598601/restart/penumbra-restart.sh)
walks every step below as confirmed prompts (detects your homes, refuses on any
mismatch):

```sh
curl -fsSL -o penumbra-restart.sh https://raw.githubusercontent.com/penumbrafi/penumbra/restart/penumbra-1-12598601/restart/penumbra-restart.sh
chmod +x penumbra-restart.sh
./penumbra-restart.sh /usr/local/bin/pd
```

### Manual steps

```sh
# 1. STOP pd and cometbft. Do not start any old-chain node again.
sudo systemctl stop penumbra   # or however you run them; stop BOTH pd and cometbft

# 2. Snapshot / full copy of node0 (rollback point). Do NOT edit or delete
#    cometbft/config/priv_validator_key.json or data/priv_validator_state.json.
cp -a node0 node0.pre-restart

# 3. Migrate: disable the 2 departed validators, write the checkpoint genesis.
ulimit -n 1048576
pd migrate-restart --home node0/pd --comet-home node0/cometbft \
  --remove 3969C0511C6ABE474757FEAB7C1B4004796D7E72 \
  --remove 9B2D4391131198750FF28EE73EC953ECFCFD06EF \
  --disable
#    log must show: 2x "removed validator" (iqlusion, polkachu), 14x "keeping",
#    "empty block 12598601 committed", then "successful migration!" with
#    post_height=12598602 and post_root=1db72ab20c0babdb8696f361d5b08d790abd8032ac64d762b138ddc80f0f99f7

# 4. VERIFY the produced genesis — MUST equal the sha below, or STOP and ask.
sha256sum node0/cometbft/config/genesis.json
#    expected: c099ccb02a2136d5071fb22b1511eeec1588ad09676e0a0532d072f28b433ed4

# 5. Check your signing state: the migration raised it to the new first height
#    and already cleared cometbft's block store (no unsafe-reset-all).
cat node0/cometbft/data/priv_validator_state.json
#    expected: "height": "12598602", "round": 0, "step": 0

# 6. Point at the KEEP set only, and disable peer exchange for the first blocks.
#    Edit node0/cometbft/config/config.toml:
#      persistent_peers = "<KEEP-set peers — provided in the coordination channel>"
#      pex = false
#    (revert pex/peers to normal after the chain is producing)

# 7. In the go-window: start pd (the migrated binary) first, then cometbft.
sudo systemctl start penumbra

# 8. Verify. The first block is 12598602 once >2/3 of the kept set is online;
#    round timeouts at 12598602 before that are expected.
curl -s localhost:26657/status | grep -o '"latest_block_height":"[0-9]*"'
#    once it passes 12598602 you are producing; block 12598602's header
#    app_hash equals post_root above.
```

---

## B. New validator (no prior penumbra-1 node)

There is no ABCI state-sync, so you bootstrap from a **state snapshot**, not from
genesis:

1. Get the post-restart snapshot from <https://snapshot.rotko.net/> (published once
   the chain is producing blocks), or take the halt-height snapshot 12598600 from
   the same place and run `pd migrate-restart` on it yourself (section A step 3):
   it produces the identical state and genesis.
2. Install `pd` v2.0.9 (section 0), restore the snapshot into your node dir.
3. Set `persistent_peers` to the KEEP set, start `pd` then `cometbft`; you will
   sync to the tip.
4. To become a validator, submit a validator definition + delegate once you are
   synced.

---

## If you miss the go-window

No problem — just do the steps above whenever you can. Your node will
block-sync to the current tip from peers and resume signing automatically. If you
are very late you may be jailed for downtime (recoverable with a one-line
`unjail`) — never tombstoned; tombstone is only for double-signing. **The only
hard rule still applies: stop the old node before starting the migrated one.**

## RPC / full nodes (non-validators)

Run steps 0–4 (step 5 is irrelevant for you; skip step 6 if you prefer). Archive
operators: copy `cometbft/data` before step 3 if you want the pre-restart block
history; the migration deletes the block store. Un-migrated nodes will reject the first block
(app-hash mismatch), so every node that follows the chain must migrate.

## Why this is safe

- This exact binary and sequence was drilled on a copy of the real halt state,
  with the signing state at 12598601 round 2 like every real validator: the
  migrated node produced blocks from 12598602 immediately, and wallets see a
  contiguous compact-block stream across 12598601. Pruned (24 GB) and unpruned
  (322 GB) copies of the state give identical hashes.
- Same chain-id, all balances/delegations preserved; removed validators are only
  disabled (no penalty) and keep their funds — they can re-enable later.
- Committed + online validators are ~73% of the kept active set (> the 2/3 needed
  to produce blocks).
- Restarting with > 1/3 of the old stake lets noble's IBC light client accept a
  relayed update, reopening the USDC bridge with no governance — if done before
  `2026-09-07 11:37 UTC`.
