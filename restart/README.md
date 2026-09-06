# penumbra-1 coordinated restart

penumbra-1 halted at height 12598600 (2026-09-02 19:37 UTC): >1/3 of stake went
offline and the core team has left, so the chain cannot resume on its own. This
branch is a continuation of penumbra-1 — same chain-id, all balances and
delegations preserved — that removes the offline validators from the active set
so the remaining operators form a quorum. No funds are touched.

The source is on this branch (`restart/penumbra-1-12598601`, off v2.0.6 /
`f833ace`): pd gains a `migrate-restart` subcommand that stock pd does not have,
because the active set lives in chain state, not `genesis.json`, and the halt bit
is unset.

## Files

- `pd-migrate-restart-v2.0.6.src.patch` — the source diff, applied on this
  branch. Kept here so operators can reproduce the binary from stock v2.0.6.
- `candidate-genesis-penumbra-1-restart-12598601-disable.json` — the reference
  genesis (539 bytes). Every operator's own `migrate-restart` must reproduce
  this exact sha256; that hash — not any prebuilt binary — is the cross-check.
- `RELEASE-SHA256SUMS` — sha256 of the patch, the reference binary, and the
  genesis, plus the post-migration app_hash (`post_root`).
- `penumbra-restart.sh` — confirmed-step operator helper. Detects pd/comet homes
  and service, stops all old-chain nodes, backs up + snapshots, runs the
  migration, verifies the genesis sha256, resets cometbft, restores
  `priv_validator_state` (tombstone guard), sets KEEP-only peers, starts, waits
  for the height to pass 12598601.
- `coordination.md` — the rally / coordination post (thresholds, deadline,
  committed set, timeline, roadmap).
- `recovery-runbook.md` — the manual runbook behind the script.
- `upgrade-process.md` — this emergency restart (path A) vs. the normal
  governance-halt upgrade used for everything after (path B, incl. pruning).
- `validator-map.tsv` — consensus address ↔ validator identity ↔ voting power.

## Key values

- chain-id: `penumbra-1` (unchanged)
- initial_height: `12598601`
- base: pd 2.0.6 (`f833ace`) + this patch
- genesis sha256: `2fa8384ff30dc5a9d6eaf3f50b80b98bef6d95c67d7cc674354b1df1d2787b1b`
- post_root: `95c5f00d71e5030c5ab7307727544c1d908002b6380786753da709a634da6a4a`
- removed from the active set (disabled, no penalty): the **2** clearly-departed
  offline validators only — **iqlusion** and **polkachu** — addresses in
  `penumbra-restart.sh` and `validator-map.tsv`. All other 14 validators are
  **kept**; uncommitted operators can rejoin by simply starting their migrated
  node (no re-bond). Committed + online ≈ 73% of the kept set (> 2/3).

## Binary

The simplest path is the **v2.0.8 recovery release** — cross-platform Linux
(x86_64 + arm64) `pd` that **includes `migrate-restart`** and is what the revived
chain runs:
<https://github.com/penumbrafi/penumbra/releases/tag/v2.0.8>

Or build from source (either produces a `pd` whose `migrate-restart` reproduces
the genesis sha below — that hash, not the binary, is the cross-check):

```
git checkout restart/penumbra-1-12598601   # (or the v2.0.8 tag)
cargo build --release -p pd
# or reproduce from stock: git checkout f833ace && git apply restart/pd-migrate-restart-v2.0.6.src.patch
```

## Deadline

noble's IBC client of penumbra (`07-tendermint-109`) expires 2026-09-07
11:37 UTC. Restart and relay a client update before then and the noble (USDC)
bridge reopens with no governance. After expiry it needs a noble governance
client substitution. Bridged funds are not destroyed either way — only the
automatic path closes.

Do not improvise. Every old-chain node must be fully stopped before the new set
starts, and `priv_validator_state` must survive the cometbft reset, or a
validator that already signed 12598601 can be tombstoned.
