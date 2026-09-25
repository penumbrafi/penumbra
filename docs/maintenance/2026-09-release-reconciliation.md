# Release reconciliation, September 2026

This records how the Penumbra source was consolidated into
`github.com/penumbrafi/penumbra` as the single canonical repository, and what
happened to every commit that was not already there. It is meant to be read
by validators and auditors: nothing below was squashed, rewritten or
silently dropped.

## Starting point (2026-09-25)

| Repository | State |
|---|---|
| `penumbra-zone/penumbra` (original upstream) | `main` at v2.1.1 (2026-01-24); maintenance line v2.0.6. No releases since. |
| `penumbrafi/penumbra` | Mirror of upstream history and branches, plus the 2.0.9 to 2.0.13 releases as tags. `main` = upstream `main` + CI and dependency fixes. |
| `rotkonetworks/penumbra` | Earlier working fork. Own `main`, diverged from upstream at v2.0.5 (`2e7563dba`); tags v2.0.7, v2.0.8. |
| Maintainer's local checkout | `main` 4 commits ahead of upstream; about 20 branches not on any remote. |

What penumbra-1 runs: the 2.0 line. The 2026-09 liveness-halt restart
activated pd 2.0.9 (`mainnet5_community_fork` migration at height 12598602).
2.0.10 to 2.0.13 add operator tooling (`pd migrate prune`, pindexer) on top.
Upstream v2.1.0 and v2.1.1 were never activated on penumbra-1.

Release tags so far are unsigned annotated tags. They will not be moved or
re-created; see "Going forward".

## Method

Every commit reachable from the rotkonetworks fork or the maintainer's local
branches, and not reachable from any `penumbrafi` branch or published tag,
was listed. Each was then compared against penumbrafi by patch content
(`git patch-id --stable`), so cherry-picked copies with different hashes
count as already present.

Result: 69 commits outside penumbrafi, of which 22 already have an identical
change on penumbrafi and 47 are unique.

## Decisions for the 47 unique commits

### Port to `release/v2.0.x` (and forward to `main`): view-side and tooling fixes, no consensus effect

| Commit | Change | Note |
|---|---|---|
| `ae57546dd` | compact-block: don't bail on `StatePayload.source = None` | view/wallet sync |
| `ee62a2628` | tct: don't panic on indexed-but-not-witnessed commitments | view/wallet sync |
| `111b4bd67` | view/worker: roll back in-memory SCT when the storage commit fails | view/wallet sync |
| `61671c321` | view: `tx_build_lock` pauses the sync worker during tx build | view/wallet sync |
| `ebf8289ac` | view: bail on out-of-order compact blocks instead of skipping | view/wallet sync |
| `e7915586e` | view/storage: fix `delete_range` omitting sct_commitments | **Needs review first:** reverted on one branch (`857043e3f`) but kept on the fork's `main`. |
| `e8a16cc86` | view: instrument `record_empty_block` stale-read diagnostic | Diagnostic only; port only if still useful. |
| `e4128d781` | `pd migrate prune`: mature-tree preflight, `--compact-source` | operator tooling |
| `0cbafbe93` | `pcli init`: import a spend key directly; fix piped stdin | client tooling |
| `47334d934` | pcli: `--output json`, refused where not implemented | client tooling |
| `135bb8031` | view: plan governance proposal actions in `TransactionPlannerRequest` | New planner request fields 78 to 80; view service only. |

None of these fixes shipped in any release tag yet.

### Consensus-relevant: `main` (2.1 line) only, after review

| Commit | Change |
|---|---|
| `dc558185e` | ibc: honor `allow_update.after_expiry` on expired client update |

### Governance documents

`366d57843`, `cf0ffadf9`, `e3345840c`, `b453311ea`: drafts of proposals 13
and 14. These go to `docs/proposals/` on `main`, not into a release branch.

### Kept as clearly-labelled experimental branches on penumbrafi, not released

| Branch | Commits | Topic |
|---|---|---|
| `zcash-custody` | `d87636e85` … `5806443b3`, `7717cfa26` (17) | Zcash Orchard threshold custody (OSST + FROST), narsild sidecar |
| `near_custody` | `2abb5067d` | NEAR custody scaffold |
| `pcli-qr-airgap` | `cda750a94`, `6f74e7d25` | pcli offline signing over QR |

### Superseded or obsolete: archived only, not ported

| Commits | Reason |
|---|---|
| `41723f76e`, `fd685c89b` (`feature/storage-pruning*`) | Superseded by `pd migrate prune`, shipped in 2.0.10. |
| `615c5a6d8`, `45d634c9b` (`restart-backup`) | Work in progress for the restart; the shipped version is `pd migrate-restart` in 2.0.9. |
| `857043e3f` | Revert; resolved together with `e7915586e` above. |
| `134855ebf` | Formatting only. |
| `350de9431`, `53b2f15f2` | npm fixes in `tct-visualize`, which has since been removed. |
| `01dae07c5`, `76b6dd600`, `4352c6956`, `d71cd7936` (`lp_linear`, 2025) | Early pcli LP/JSON work; superseded by `47334d934` and later LP changes. |

The rotkonetworks fork is archived read-only rather than deleted, so every
hash above stays resolvable.

### Tags

`v2.0.7` (`918fdff7c`) and `v2.0.8` (`009fc3de9`) existed only on the
rotkonetworks fork. Their commits are already on penumbrafi
(`prune/2.0.x`); the tags were added to penumbrafi unchanged on 2026-09-25.

## Branches after reconciliation

| Branch | Role |
|---|---|
| `release/v2.0.x` | What penumbra-1 runs. Fast-forwarded on 2026-09-25 from v2.0.6 (`f833ace04`) to `4232d1dc0` (v2.0.13 plus fork metadata and the CI revert to upstream release.yml). Consensus-compatible fixes only. |
| `main` | Next consensus version, the 2.1 line: upstream v2.1.1 with `release/v2.0.x` merged in (a merge, so all 2.0 tags stay reachable). |
| `release/v2.1.x` | Cut from `main` when 2.1.2 is released. |

The per-patch branches `release/v2.0.10`, `release/v2.0.11` and
`release/2.0.12` are removed once `release/v2.0.x` contains them; every
commit on them stays reachable from `release/v2.0.x` and its tags.

## Going forward

- Release tags are signed, and every GitHub release publishes sha256
  checksums for each binary.
- Release notes open with an operator box: consensus-compatible yes/no,
  required yes/no, deadline or halt height, migration steps.
- A patch release (2.0.x to 2.0.y) is a drop-in replacement. A minor release
  (2.0 to 2.1) changes consensus and activates only at a height set by a
  governance upgrade proposal.

## Full commit list

`status` is `UNIQUE` or `equivalent-on-penumbrafi` (identical change already
present under another hash). Sources: `rotko:` = rotkonetworks/penumbra
branch, `local:` = maintainer's local branch, `tag:` = tag.

| Commit | Date | Status | Subject | Sources |
|---|---|---|---|---|
| `01dae07c5` | 2025-06-22 | UNIQUE | add raw json option for lp | local:lp_linear,rotko:archive/main-pre-pd2.0.6-20260714,rotko:feat/pcli_json,rotko:json_dex,rotko:lp_linear |
| `76b6dd600` | 2025-06-29 | UNIQUE | rm warnings | local:lp_linear,rotko:archive/main-pre-pd2.0.6-20260714,rotko:feat/pcli_json,rotko:json_dex,rotko:lp_linear |
| `4352c6956` | 2025-06-29 | UNIQUE | pumpbinaries | local:lp_linear,rotko:archive/main-pre-pd2.0.6-20260714,rotko:feat/pcli_json,rotko:json_dex,rotko:lp_linear |
| `53b2f15f2` | 2025-09-09 | UNIQUE | fix:patch npm vulnerabilities | local:lp_linear,rotko:archive/main-pre-pd2.0.6-20260714,rotko:feat/pcli_json,rotko:lp_linear |
| `350de9431` | 2025-09-09 | UNIQUE | fix: patch npm vulnerabilities in tct-visualize | rotko:npm_patch |
| `d71cd7936` | 2025-10-22 | UNIQUE | fix: LP position creation UX + GCC 15 compatibility | local:lp_linear,rotko:archive/main-pre-pd2.0.6-20260714,rotko:lp_linear |
| `2abb5067d` | 2025-12-08 | UNIQUE | init | local:near_custody |
| `cda750a94` | 2025-12-10 | UNIQUE | feat(pcli): add offline signing support with QR codes and schema commands | rotko:pcli-qr-airgap |
| `41723f76e` | 2025-12-18 | UNIQUE | feat(pd): implement manual storage pruning for JMT historical data | local:feature/storage-pruning,rotko:feature/storage-pruning |
| `fd685c89b` | 2025-12-18 | UNIQUE | feat(pd): implement manual storage pruning for JMT historical data | local:feature/storage-pruning-2.0.x,rotko:feature/storage-pruning-2.0.x |
| `6f74e7d25` | 2025-12-18 | UNIQUE | feat(pcli): add offline signing support with QR codes and schema commands | local:pcli-qr-airgap |
| `679f4d3d7` | 2026-03-15 | UNIQUE | fix(custody/zcash): address review findings | local:zcash-custody,rotko:zcash-custody |
| `118b49ca9` | 2026-03-15 | UNIQUE | feat(custody/zcash): end-to-end RedPallas FROST signing | local:zcash-custody,rotko:zcash-custody |
| `4e560f8f0` | 2026-03-15 | UNIQUE | feat(custody/zcash): governance-togglable accountability mode | local:zcash-custody,rotko:zcash-custody |
| `cd34a03bd` | 2026-03-15 | UNIQUE | doc(custody/zcash): signed OSST contributions for accountability | local:zcash-custody,rotko:zcash-custody |
| `cf15b18a7` | 2026-03-15 | UNIQUE | fix(custody/zcash): review fixes | local:zcash-custody,rotko:zcash-custody |
| `ed6498f63` | 2026-03-15 | UNIQUE | doc(custody/zcash): custody cap governance → DEX oracle path | local:zcash-custody,rotko:zcash-custody |
| `896c021c3` | 2026-03-15 | UNIQUE | security(custody/zcash): document FROST economic security model | local:zcash-custody,rotko:zcash-custody |
| `0d39acbb1` | 2026-03-15 | UNIQUE | fix(custody/zcash): FROST threshold 2-of-5 | local:zcash-custody,rotko:zcash-custody |
| `d1b68e905` | 2026-03-15 | UNIQUE | feat(custody/zcash): real RedPallas FROST keygen via reddsa | local:zcash-custody,rotko:zcash-custody |
| `d87636e85` | 2026-03-15 | UNIQUE | feat(custody): Zcash Orchard threshold custody via OSST+FROST | local:zcash-custody,rotko:zcash-custody |
| `b67d4b0ff` | 2026-03-16 | UNIQUE | fix(token-factory): adapt to 2.1.1 API changes | local:zcash-custody,rotko:zcash-custody |
| `80dc998bb` | 2026-03-16 | UNIQUE | fix: restore Cargo.toml after token-factory rebase | local:zcash-custody,rotko:zcash-custody |
| `c6c40495b` | 2026-03-16 | equivalent-on-penumbrafi | pcli: add token-factory view and query commands | local:zcash-custody,rotko:zcash-custody |
| `70163b6a7` | 2026-03-16 | equivalent-on-penumbrafi | component(token-factory): add query service for token metadata | local:zcash-custody,rotko:zcash-custody |
| `8cf17ec84` | 2026-03-16 | equivalent-on-penumbrafi | pcli: add token-factory launch command with bonding curve | local:zcash-custody,rotko:zcash-custody |
| `85407ba4e` | 2026-03-16 | equivalent-on-penumbrafi | view: add action_burn to planner | local:zcash-custody,rotko:zcash-custody |
| `926d1b9ba` | 2026-03-16 | equivalent-on-penumbrafi | pcli: display burn actions in transaction view | local:zcash-custody,rotko:zcash-custody |
| `fd93bf193` | 2026-03-16 | equivalent-on-penumbrafi | app: register ActionBurn handler | local:zcash-custody,rotko:zcash-custody |
| `80608e8ab` | 2026-03-16 | equivalent-on-penumbrafi | transaction: wire up ActionBurn through action dispatch | local:zcash-custody,rotko:zcash-custody |
| `3b2788d79` | 2026-03-16 | equivalent-on-penumbrafi | shielded-pool: add generic ActionBurn for any value type | local:zcash-custody,rotko:zcash-custody |
| `22545431c` | 2026-03-16 | equivalent-on-penumbrafi | pcli: add token-factory subcommand | local:zcash-custody,rotko:zcash-custody |
| `bf47e1df8` | 2026-03-16 | equivalent-on-penumbrafi | view: planner support for token factory | local:zcash-custody,rotko:zcash-custody |
| `af475211e` | 2026-03-16 | equivalent-on-penumbrafi | app: register token factory action handlers | local:zcash-custody,rotko:zcash-custody |
| `c707c9f58` | 2026-03-16 | equivalent-on-penumbrafi | transaction: wire up token factory actions | local:zcash-custody,rotko:zcash-custody |
| `99bc1e2c3` | 2026-03-16 | equivalent-on-penumbrafi | component(token-factory): initial implementation | local:zcash-custody,rotko:zcash-custody |
| `76ab7d534` | 2026-03-16 | UNIQUE | feat(custody/zcash): interactive DKG — no trusted dealer | local:zcash-custody,rotko:zcash-custody |
| `cf819329d` | 2026-03-17 | UNIQUE | feat(narsild): DKG ceremony + peer broadcast + OSST threshold | local:zcash-custody |
| `5806443b3` | 2026-03-17 | UNIQUE | feat(narsild): OSST authorization sidecar for validators | local:zcash-custody |
| `ebf8289ac` | 2026-03-26 | UNIQUE | fix(view): bail on out-of-order compact blocks instead of skipping | local:fix/ibc-allow-update-after-expiry,local:fix/view-worker-sct-divergence,rotko:fix/ibc-allow-update-after-expiry,rotko:fix/view-worker-sct-divergence |
| `7717cfa26` | 2026-04-14 | UNIQUE | feat: Zcash Orchard threshold custody via RedPallas FROST | local:fix/ibc-allow-update-after-expiry |
| `dc558185e` | 2026-04-14 | UNIQUE | fix(ibc): honor allow_update.after_expiry on expired client updates | local:fix/ibc-allow-update-after-expiry,rotko:fix/ibc-allow-update-after-expiry |
| `ae57546dd` | 2026-06-03 | UNIQUE | compact-block: don't bail on StatePayload.source = None | local:ci/github-runners,local:fix/worker-sct-rollback-on-storage-err,local:tct-graceful-witness,local:worktree-agent-afca657418fb105b2,rotko:fix/worker-sct-rollback-on-storage-err,rotko:main,rotko:p2.0.6-tx-build-lock,rotko:tct-graceful-witness |
| `ee62a2628` | 2026-06-03 | UNIQUE | tct: don't panic on indexed-but-not-witnessed commitments | local:ci/github-runners,local:fix/worker-sct-rollback-on-storage-err,local:tct-graceful-witness,local:worktree-agent-afca657418fb105b2,rotko:fix/worker-sct-rollback-on-storage-err,rotko:main,rotko:p2.0.6-tx-build-lock,rotko:tct-graceful-witness |
| `e7915586e` | 2026-06-04 | UNIQUE | view/storage: fix delete_range omitting sct_commitments | local:ci/github-runners,local:fix/worker-sct-rollback-on-storage-err,local:tct-graceful-witness,local:worktree-agent-afca657418fb105b2,rotko:fix/worker-sct-rollback-on-storage-err,rotko:main,rotko:p2.0.6-tx-build-lock,rotko:tct-graceful-witness |
| `857043e3f` | 2026-06-05 | UNIQUE | Revert "view/storage: fix delete_range omitting sct_commitments" | local:tct-graceful-witness,rotko:tct-graceful-witness |
| `e8a16cc86` | 2026-06-07 | UNIQUE | view: instrument record_empty_block stale-read diagnostic | local:ci/github-runners,local:fix/worker-sct-rollback-on-storage-err,local:worktree-agent-afca657418fb105b2,rotko:fix/worker-sct-rollback-on-storage-err,rotko:main,rotko:p2.0.6-tx-build-lock |
| `111b4bd67` | 2026-06-07 | UNIQUE | view/worker: rollback in-memory SCT when storage commit fails | local:ci/github-runners,local:fix/worker-sct-rollback-on-storage-err,local:worktree-agent-afca657418fb105b2,rotko:fix/worker-sct-rollback-on-storage-err,rotko:main,rotko:p2.0.6-tx-build-lock |
| `61671c321` | 2026-07-14 | UNIQUE | fix(view): tx_build_lock to pause sync worker during tx build | local:ci/github-runners,local:worktree-agent-afca657418fb105b2,rotko:main,rotko:p2.0.6-tx-build-lock |
| `bae136e4b` | 2026-09-06 | equivalent-on-penumbrafi | ci: run workflows on GitHub-hosted runners | local:ci/github-runners,local:worktree-agent-afca657418fb105b2,rotko:main |
| `615c5a6d8` | 2026-09-06 | UNIQUE | pd: add restart-mainnet-1 migration for the 2026-09-02 liveness halt | local:restart-backup |
| `45d634c9b` | 2026-09-06 | UNIQUE | wip: restart-mainnet-1 migration | local:restart-backup |
| `134855ebf` | 2026-09-06 | UNIQUE | style: cargo fmt | local:worktree-agent-afca657418fb105b2,rotko:main |
| `e26097355` | 2026-09-06 | equivalent-on-penumbrafi | pmonitor: replace deleted process-compose-openapi-client dev-dependency | local:worktree-agent-afca657418fb105b2,rotko:main |
| `8471589e4` | 2026-09-13 | equivalent-on-penumbrafi | remove tct-visualize crate — pulls a vulnerable JS dep, not used in prod | local:chore/remove-tct-visualize,local:feat/pindexer-notify-and-gap-skip |
| `16ce9f1d5` | 2026-09-13 | equivalent-on-penumbrafi | pindexer: skip gap blocks in dex_ex, emit pg_notify per commit | local:feat/pindexer-notify-and-gap-skip |
| `56b722eb2` | 2026-09-13 | equivalent-on-penumbrafi | qa/fv: document the IBC boundary as out-of-scope Phase-2 (Kani + Quint) | local:feat/pindexer-notify-and-gap-skip |
| `cc09017ab` | 2026-09-13 | equivalent-on-penumbrafi | qa/fv: circuit layer frame-complete — SwapClaim/DelegatorVote/NullifierDerivation | local:feat/pindexer-notify-and-gap-skip |
| `260c2c3bf` | 2026-09-13 | equivalent-on-penumbrafi | qa/fv: deps reconciliation — Clean + mathlib verified on Lean 4.33.1 | local:feat/pindexer-notify-and-gap-skip |
| `2b8582c3d` | 2026-09-13 | equivalent-on-penumbrafi | qa/fv: parallel Fable frame batch — Spend/Output/Swap value-accounting obligations | local:feat/pindexer-notify-and-gap-skip |
| `740c6e0c2` | 2026-09-13 | equivalent-on-penumbrafi | qa/fv: opening draft — no-counterfeiting formal verification scaffold | local:feat/pindexer-notify-and-gap-skip |
| `e4128d781` | 2026-09-18 | UNIQUE | perf(pd migrate prune): mature-tree preflight + --compact-source | local:perf/prune-preflight-and-compact |
| `0cbafbe93` | 2026-09-22 | UNIQUE | pcli init: import a spend key directly, and fix piped stdin | local:feat/pcli-init-import-key |
| `47334d934` | 2026-09-24 | UNIQUE | pcli: `--output json`, and a gate that refuses it where it is not implemented | local:feat/planner-governance-actions,local:governance/proposals-13-14,local:main |
| `b453311ea` | 2026-09-24 | UNIQUE | docs(proposals): drop INJ from proposal 13's routing candidates | local:governance/proposals-13-14 |
| `e3345840c` | 2026-09-24 | UNIQUE | docs(proposals): raise tranche 4 to 8,000 UM per epoch | local:governance/proposals-13-14 |
| `cf0ffadf9` | 2026-09-24 | UNIQUE | docs(proposals): disclose rotko.net as largest LP in tranche 4 | local:governance/proposals-13-14 |
| `366d57843` | 2026-09-24 | UNIQUE | docs(proposals): governance proposals 13 and 14, drafts for joint submission | local:governance/proposals-13-14 |
| `135bb8031` | 2026-09-25 | UNIQUE | view: plan governance proposal actions in TransactionPlannerRequest | local:feat/planner-governance-actions |
