# penumbra-1 coordinated restart — validator runbook

penumbra-1 halted at height **12598600**. This restart continues the **same
chain-id** (`penumbra-1`) — all balances and delegations preserved — by disabling
the two departed validators (iqlusion, polkachu) and keeping the other 14. Every
kept validator can rejoin.

## Key values (verify against these)

| | |
|---|---|
| restart height | `12598601` |
| genesis sha256 | `2fa8384ff30dc5a9d6eaf3f50b80b98bef6d95c67d7cc674354b1df1d2787b1b` |
| app_hash / post_root | `95c5f00d71e5030c5ab7307727544c1d908002b6380786753da709a634da6a4a` |
| removed (disabled, no penalty) | iqlusion `3969C0511C6ABE474757FEAB7C1B4004796D7E72`, polkachu `9B2D4391131198750FF28EE73EC953ECFCFD06EF` |
| go-window | **SET BY COORDINATORS** (before the noble client expiry `2026-09-07 11:37 UTC`) |

**The one hard rule:** fully stop your old halted node before starting the
migrated one. Running the old and new node on the same key = double-sign =
permanent tombstone.

**Verify, don't trust:** your own `pd migrate-restart` must reproduce the exact
genesis sha256 above. That hash — not any prebuilt binary — is the cross-check.

---

## 0. Get the binary

Download `pd` **v2.0.8** (Linux x86_64 or arm64) — it includes `migrate-restart`
and is what the revived chain runs:
<https://github.com/penumbrafi/penumbra/releases/tag/v2.0.8>

```sh
# example, x86_64:
curl -fsSL -o pd.tar.gz https://github.com/penumbrafi/penumbra/releases/download/v2.0.8/pd-x86_64-unknown-linux-gnu.tar.gz
tar xzf pd.tar.gz && sudo install pd-x86_64-unknown-linux-gnu/pd /usr/local/bin/pd
pd --version    # -> pd 2.0.8
```

Or build from source (see `restart/README.md`). Either way `pd migrate-restart`
must reproduce the genesis sha above.

---

## A. Existing validator (you ran penumbra-1 before the halt)

You have your halted node dir with `pd/` (rocksdb) and `cometbft/`. Adjust the
paths below to your layout.

### The easy path
`restart/penumbra-restart.sh` walks every step below as confirmed prompts
(detects your homes, refuses on any mismatch):

```sh
./penumbra-restart.sh /usr/local/bin/pd
```

### Manual steps

```sh
# 1. STOP pd and cometbft. Do not start any old-chain node again.
sudo systemctl stop penumbra   # or however you run them; stop BOTH pd and cometbft

# 2. Back up signing state + snapshot the node (rollback point).
cp -a node0/cometbft/data/priv_validator_state.json /safe/pvs.json
#    (zfs snapshot / full copy of node0 strongly recommended)

# 3. Migrate: disable the 2 departed validators, write the checkpoint genesis.
ulimit -n 1048576
pd migrate-restart --home node0/pd --comet-home node0/cometbft \
  --remove 3969C0511C6ABE474757FEAB7C1B4004796D7E72 \
  --remove 9B2D4391131198750FF28EE73EC953ECFCFD06EF \
  --disable
#    log must show: removed=2 kept=14, halted=false,
#    post_root=95c5f00d71e5030c5ab7307727544c1d908002b6380786753da709a634da6a4a

# 4. VERIFY the produced genesis — MUST equal the sha below, or STOP and ask.
sha256sum node0/cometbft/config/genesis.json
#    expected: 2fa8384ff30dc5a9d6eaf3f50b80b98bef6d95c67d7cc674354b1df1d2787b1b

# 5. Reset cometbft data, then RESTORE your signing state (tombstone guard).
cometbft unsafe-reset-all --home node0/cometbft
cp -a /safe/pvs.json node0/cometbft/data/priv_validator_state.json

# 6. Point at the KEEP set only, and disable peer exchange for the first blocks.
#    Edit node0/cometbft/config/config.toml:
#      persistent_peers = "<KEEP-set peers — provided in the coordination channel>"
#      pex = false
#    (revert pex/peers to normal after the chain is producing)

# 7. In the go-window: start pd (the migrated binary) first, then cometbft.
sudo systemctl start penumbra

# 8. Verify. Expect ~3 timeout rounds (~1 min) before 12598601 lands, since your
#    key already signed rounds 0-2 at that height on the old chain.
curl -s localhost:26657/status | grep -o '"latest_block_height":"[0-9]*"'
#    once it passes 12598601 you are producing.
```

---

## B. New validator (no prior penumbra-1 node)

There is no ABCI state-sync, so you bootstrap from a **state snapshot**, not from
genesis:

1. Get a snapshot of a migrated node's state at height `12598601` from an existing
   operator (coordination channel), plus the `config/genesis.json`
   (sha `2fa8384f…`).
2. Install `pd` v2.0.8 (section 0), restore the snapshot into your node dir.
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

Run steps 0–4 (skip the `priv_validator_state` restore in step 5, and skip step 6
peer restrictions if you prefer). Un-migrated nodes will reject the first block
(app-hash mismatch), so every node that follows the chain must migrate.

## Why this is safe

- This exact sequence (migrate-restart removing a departed validator → cometbft
  reset → restore `priv_validator_state` → restart) was drilled on a multi-validator
  devnet with the v2.0.8 binary: the kept validator resumed producing blocks past
  the restart height with no tombstone, no double-sign, and no re-init error.
- Same chain-id, all balances/delegations preserved; removed validators are only
  disabled (no penalty) and keep their funds — they can re-enable later.
- Committed + online validators are ~73% of the kept active set (> the 2/3 needed
  to produce blocks).
- Restarting with > 1/3 of the old stake lets noble's IBC light client accept a
  relayed update, reopening the USDC bridge with no governance — if done before
  `2026-09-07 11:37 UTC`.
