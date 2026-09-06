# Penumbra penumbra-1 — coordinated restart

penumbra-1 halted at height 12598600 on 2026-09-02 19:37 UTC. Two large
validators — Iqlusion (30%) and Polkachu (14.8%) — stopped deliberately, and the
core team has left. The remaining online stake is below 2/3, so the chain cannot
resume on its own.

This is a continuation of penumbra-1, not a new chain: same chain-id, all
balances, delegations and history preserved. The offline validators are removed
from the active set so the remaining operators form the quorum. No funds are
touched.

## Deadline

noble's IBC light client of penumbra (`07-tendermint-109`, trust level 1/3,
trusting period 4.67 days) was last updated at the halt. It expires 2026-09-07
11:37 UTC. If we restart and refresh it before then, the client follows via a
normal relayed update — no governance. After expiry, reopening the bridge needs
a noble governance client substitution, which is slower and depends on noble
acting. Bridged assets are not destroyed either way; only the automatic path
closes at expiry.

## Threshold

Two different numbers. Do not confuse them.

- Reopen the noble bridge without governance: the restart must be signed by more
than 1/3 of the old stake (33.3%).
- Produce blocks: the new active set is whoever restarts, so 2/3 of the new set
is satisfied by construction. 2/3 of the old set is not a target and is not
reachable — 44.8% of it is gone.

## Committed — 34.5%, enough to reopen the bridge

- rotko.net — 18.5% (coordinating)
- antumbra.net — 7.4%
- ghostinnet — 4.9%
- Bryanlabs — 3.7%

## Tick to join the active set

- [ ] CryptoCrew — 4.0%
- [ ] Tessellated — 3.7%
- [ ] silent — 3.6%
- [ ] Architect Nodes — 3.4%
- [ ] MathNodes — 1.8%
- [ ] Pro-Delegators — 1.2%
- [ ] AM Solutions — 0.9%
- [ ] OriginStake — 0.7%
- [ ] Validatus — 0.7%
- [ ] PathrockNetwork — 0.7%

More operators means a less concentrated set and a stronger restart. If you do
not tick in, your validator is left out of the active set; your balances and
delegations are preserved and you can re-bond after the restart.

## Timeline

- Tick in within 12 hours of this post.
- Genesis, binary and sha256 published: 2026-09-06 06:00 UTC.
- Coordinated restart follows, before the noble client expires at 2026-09-07
11:37 UTC.

## How the restart works

The active validator set is not a field in genesis.json — pd derives it from
chain state. The restart therefore uses a specific migration binary and a
genesis that Rotko builds, tests against a copy of the halted state, and
distributes. The binary is reproducible: rebuild it and match the hash rather
than trusting the file. Stock `pd migrate` does not perform this restart.

Each operator, at go-time (a confirmed-step script does all of this):

- stop penumbra; confirm every old-chain node you run is down
- back up priv_validator_state and snapshot the node
- run the distributed migration (`pd migrate-restart … --disable`) — it produces
the genesis from your own state
- verify the produced genesis sha256 matches the published value
- reset cometbft, then restore priv_validator_state (tombstone guard)
- set KEEP-only peers, start, confirm the height passes 12598601

Start order: antumbra.net + ghostinnet + Bryanlabs first (chain idle, no
quorum), then rotko.net last — so the first block is signed by all four and is
usable for the noble update.

Same validator key, same identity. Exact commands ship with the release.

Safety: every old-chain node must be fully stopped before the new set starts,
and priv_validator_state must be preserved across the reset. Validators that
already signed height 12598601 can be tombstoned if this is done wrong. Follow
the runbook exactly; do not improvise.

## Parameters

- chain-id: penumbra-1 (unchanged)
- initial_height: 12598601
- base binary: pd 2.0.6 with the restart migration (reproducible from a 21 KB
source patch)
- genesis sha256:
`386a4f58f53316e7c410f860bba6ee5c8cf0acd97bca808cb874a80b951788a8` (539 bytes) —
every operator's migration must reproduce this exact hash
- removed from the active set (disabled, no penalty): iqlusion, polkachu, and
every operator not ticked in

## Roadmap after the restart

The restart is step one. The rest, in order, prioritised by value at stake so
people can get every bridged asset out — not just USDC:

1. **Phase 1 — restart (this document).** Revive penumbra-1 and reopen the
   **noble (USDC)** bridge, the largest bridged balance. Withdrawals to noble
work again.
2. **Phase 2 — upgrade to latest pd + enable pruning.** A normal governance-halt
   upgrade once the chain is stable (~1–2 weeks out). Chain state drops from
~322 GB to a fraction, so running a validator is cheap — fixing the cost that
emptied the set in the first place. Uses the standard halt→`pd migrate`→restart
path, not the emergency fork.
3. **Phase 3 — recover the remaining IBC channels, one at a time, by value.**
   Unlike noble (whose client is still alive — just relay), every other
counterparty client is already **expired on both sides**, so each needs a
**counterparty governance client substitution** (`MsgRecoverClient`), not a
simple relayed update. So we go by value and only where it's worth the ask:
**stride → cosmos hub → osmosis**, one at a time, verified before the next. The
sub-$300 tail (celestia, neutron, dydx, axelar) only if it's trivial.

**Value at stake per channel (≈ $86.3k total; noble+stride+hub = 91%):**

| Channel | Asset | ~USD | Client status |
|---|---|---|---|
| noble | 39,783 USDC + 425 USDY | **$40,270** | active — expires ~2026-09-07 11:37 UTC (Phase 1) |
| stride | stATOM / stOSMO / stTIA / STRD | **$26,450** | expired → governance |
| cosmos hub | 7,836 ATOM | **$12,220** | expired → governance |
| osmosis | 29,543 OSMO + allETH/BTC + memecoins | **~$7,040** | expired → governance |
| celestia | 680 TIA | $260 | expired |
| neutron / dydx / axelar | dust | <$20 | expired |

## Notes

- Is my stake safe? Yes. All balances and delegations carry forward. Removing a
validator removes its consensus role, not anyone's funds.
- New key? No. Same key, same identity.
- Is this a hostile fork? No. The chain is halted and those validators left
voluntarily. This is the remaining operators continuing penumbra-1.
- Just want your funds out? The >1/3 restart reopens the noble bridge; that is
what lets you withdraw.
