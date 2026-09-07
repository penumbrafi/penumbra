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

- Full source diff, stock v2.0.6 to the v2.0.9 tag: <https://github.com/penumbrafi/penumbra/compare/v2.0.6...v2.0.9>
  (also in `pd-2.0.9-vs-2.0.6.src.patch`). Review this; it is everything the
  recovery binary changes.
- `candidate-genesis-penumbra-1-restart-12598602-disable.json` — the reference
  genesis (539 bytes). Every operator's own `migrate-restart` must reproduce
  this exact sha256; that hash — not any prebuilt binary — is the cross-check.
- `RELEASE-SHA256SUMS` — sha256 of the patch, the reference binary, and the
  genesis, plus the post-migration app_hash (`post_root`).
- `penumbra-restart.sh` — confirmed-step operator helper. Detects pd/comet homes
  and service, stops all old-chain nodes, backs up + snapshots, runs the
  migration, verifies the genesis sha256, resets cometbft, restores
  `priv_validator_state` (tombstone guard), sets KEEP-only peers, starts, waits
  for the height to pass 12598602.
- `coordination.md` — the rally / coordination post (thresholds, deadline,
  committed set, timeline, roadmap).
- `recovery-runbook.md` — the manual runbook behind the script.
- `upgrade-process.md` — this emergency restart (path A) vs. the normal
  governance-halt upgrade used for everything after (path B, incl. pruning).
- `validator-map.tsv` — consensus address ↔ validator identity ↔ voting power.

## Key values

- chain-id: `penumbra-1` (unchanged)
- initial_height: `12598602` (the migration executes an empty application block 12598601
  itself; see RESTART-STEPS.md, "Why the restart height is 12598602")
- base: pd 2.0.6 (`f833ace`) + this branch, released as **pd 2.0.9**
- genesis sha256: `c099ccb02a2136d5071fb22b1511eeec1588ad09676e0a0532d072f28b433ed4`
- post_root: `1db72ab20c0babdb8696f361d5b08d790abd8032ac64d762b138ddc80f0f99f7`
- removed from the active set (disabled, no penalty): the **2** clearly-departed
  offline validators only — **iqlusion** and **polkachu** — addresses in
  `penumbra-restart.sh` and `validator-map.tsv`. All other 14 validators are
  **kept**; uncommitted operators can rejoin by simply starting their migrated
  node (no re-bond). Committed + online ≈ 73% of the kept set (> 2/3).

## Binary

> **pd 2.0.10 is a superset of 2.0.9.** It is 2.0.9 plus the offline
> `pd migrate prune` tool; `migrate-restart` and the genesis it produces are
> byte-identical. If you have not restarted yet, use
> <https://github.com/penumbrafi/penumbra/releases/tag/v2.0.10> and substitute
> `2.0.10` for `2.0.9` in the commands below; the genesis sha256 and the
> post-migration app_hash are unchanged. Pruning is a separate, optional,
> offline step — see `CHANGELOG.md` — and must not be run within 24 h of the
> restart on a validator.

The simplest path is the **v2.0.9 recovery release** — Linux x86_64 `pd` (arm64: build from source) that **includes `migrate-restart`** and is what the revived
chain runs:
<https://github.com/penumbrafi/penumbra/releases/tag/v2.0.9>
(v2.0.8 and the 2.0.6 branch builds restart at 12598601 and cannot start the chain; do not use them)

Or build from source (either produces a `pd` whose `migrate-restart` reproduces
the genesis sha below — that hash, not the binary, is the cross-check):

```
git checkout restart/penumbra-1-12598601   # (or the v2.0.9 tag)
cargo build --release -p pd
```

## Deadline

noble's IBC client of penumbra (`07-tendermint-109`) expires 2026-09-07
11:37 UTC. Restart and relay a client update before then and the noble (USDC)
bridge reopens with no governance. After expiry it needs a noble governance
client substitution. Bridged funds are not destroyed either way — only the
automatic path closes.

Do not improvise. Every old-chain node must be fully stopped before the new set
starts, and `priv_validator_state.json` must never be hand-edited; the migration
raises it to 12598602 itself.
