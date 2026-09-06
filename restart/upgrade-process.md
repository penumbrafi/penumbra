# Penumbra (revived chain) — upgrade process & schedule

Two kinds of migration. They are not the same and must not be confused.

## A. Emergency restart — Phase 1, one-time (what we are doing now)
Cause: liveness halt (>1/3 offline) + a validator-set change. Stock pd cannot do this — the halt
bit is unset and the validator set lives in state, not genesis. Requires the forked
`pd migrate-restart`. This is a one-off to bring the chain back. Not used again unless the chain
dies the same way.

## B. Normal upgrade — Phase 2 onward (every future change, incl. pruning)
Clean, repeatable, stock tooling — the standard Penumbra upgrade path:

1. Agree the change: new binary + a halt height + a date. On-chain governance proposal once the
   chain is healthy; while the validator set is small, a coordinated agreement among the KEEP set.
2. Each validator builds the new binary from source and confirms it is reproducible (sha-match)
   *before* the halt height.
3. Dry-run the migration on a ZFS clone of a node; publish the expected post-migration app_hash and
   genesis sha256 so everyone cross-checks (same method we used for the restart).
4. Chain halts cleanly at the height (halt bit set by the upgrade).
5. Each validator: `pd migrate --home <pd> --comet-home <comet> --ready-to-start` (works because the
   halt bit IS set), then restart on the new binary.
6. Confirm all validators producing on the new version.

No forked binary, no validator-set surgery.

## Discipline (every upgrade)
- One logical change per upgrade. Do not bundle unrelated risk (this is why pruning is not in the restart).
- Always dry-run on a `zfs clone` first; publish expected hashes.
- Reproducible binary; operators build and sha-match rather than trusting a blob.
- `zfs snapshot` every node immediately before the halt — the rollback point.

## Schedule
- **Phase 1 — emergency restart:** now, before the noble client expiry (2026-09-07 11:37 UTC).
  2.0.6, validator-set change only. Tested genesis `386a4f58…`.
- **Phase 2 — pruning upgrade:** ~1–2 weeks after Phase 1 is stable. Harden the cnidarium-pruning
  branch (`prune/erwan-5272-rebased`), dry-run on a clone, schedule a halt height, migrate via path B.
  Result: chain state drops from ~322 GB to a fraction — cheap to run, which is what makes a small
  validator set sustainable and lets operators come back.
- **Later:** track upstream / latest pd as needed, each via path B, one change at a time.
