# Validator-set custody: a shielded bridge for pZEC and pBTC

Status: **design, for review**. Revised 2026-09-21.

This document replaces two earlier and partly contradictory drafts —
`docs/design/validator-custody-bridge.md` (the BTC/ZEC shared framework) and
`docs/design/zcash-shielded-bridge.md` (the Orchard-specific sketch). Where
they disagreed, this one decides; where one of them was wrong, the correction
is marked. It also supersedes `zcli/docs/design/validator-frost-custody.md`
and the two-layer OSST + committee design on the `zcash-custody` branch.

Nothing described here is implemented end to end and none of the cryptography
involved has been audited.

---

## 1. Goal and shape

**Goal.** A bridge, not a treasury. ZEC or BTC sent to an escrow address that
the Penumbra validator set holds under a threshold key is credited on Penumbra
as a wrapped asset (`pZEC`, `pBTC`). Burning the wrapped asset produces a
withdrawal that the validator set signs. Nobody but the validator set can move
the underlying, and the validator set can only move it in response to chain
state.

For Zcash both legs are shielded: the escrow is an Orchard address and the
Penumbra side is an ordinary shielded note.

**Shape.** One layer, not two. An earlier design had all validators authorize
via stake-weighted OSST proofs and a small FROST committee execute. Nothing on
Bitcoin or Zcash checks an OSST proof, so the committee was the real custodian.
Here the threshold signature **is** the authorization: `t` of the `n` active
validators must sign, and a signer that signs anything the chain did not order
is attributable by index and slashable.

**Threshold.** 6-of-11 at the current active-set size, unweighted, reshared at
epoch boundaries, with key rotation on the trigger in §9.

| | 6-of-11 | 7-of-11 |
|---|---|---|
| Colluders required to steal | 6 | 7 |
| Members offline before withdrawals stall | 5 | 4 |
| Dealers required to reshare | 6 | 7 |

Shares are only as independent as the hosts, playbooks and people behind them,
and trust in today's eleven does not transfer to whoever holds a seat in two
years. Accountability (§3) and rotation (§9) exist for the second case.
Weighted shares are a non-goal for v1; see §10 for where the weighted code
stands.

**Nested positions are a per-validator choice.** A nested FROST v2 position is
indistinguishable from a flat signer, so a validator may hold its single share
as an inner group across its own hosts or HSMs, and reshare that inner group,
without the escrow key, the other validators or the chain component changing.
The chain component is deliberately blind to it. Gate: the v2 equivalence claim
needs external review first (§10).

**Process split.** The chain component lives in `pd`. The signer does not:
`pd` state is restored from snapshots and state-sync, which the nonce rule in
§6.4 forbids. The signer ships as a `pd custody-signer` subcommand in the same
binary and config, run as a separate process against the local `pd` gRPC.

---

## 2. Parameters

| | Zcash (pZEC) | Bitcoin (pBTC) |
|---|---|---|
| Curve / ciphersuite | Pallas, RedPallas spend-auth via FROST(Pallas, BLAKE2b-512) | secp256k1, BIP340 |
| Escrow key | Orchard spend authorizing key `ask`, threshold-held; `nk` + `fvk` held by the prover set (§7.3) | Taproot key-path P2TR |
| Signing library | `frost-spend` (ZF `frost-core` 2.2), `OrchardSpendAuthCurve` backend | `frostsnap_core` / `schnorr_fun` |
| DKG / reshare math | `osst` (frostito): sealed interleaved Feldman VSS, key-preserving reshare | same, ported to `secp256kfun` types |
| Deposit detection | Orchard trial decryption with the escrow **incoming** viewing key | SPV against a header chain `pd` tracks |
| Deposit routing | ZIP-302 structured memo carrying the Penumbra address | `OP_RETURN` or a per-user deposit address |
| Transport between signers | ZF `frostd` relay, Noise_K sealed round 2 | same |
| n / t | 11 / 6 | 11 / 6 |
| Deposit finality depth `N` | 60 blocks (~75 min), governance parameter | 12 blocks (~2 h), governance parameter |

**One stack per role.** DKG, reshare and sealing are `osst`. Orchard
transaction construction, PCZT handling and the RedPallas spend-auth signature
are `frost-spend`. The outer signing group is flat 6-of-11; nested FROST v2 is
used only where a validator chooses to split its own position, and by the
escrow-network follow-on. The two earlier drafts each named a different stack
as canonical; this table is the answer.

Epochs are Penumbra epochs. "Custody epoch" and "chain epoch" are the same
thing, since the chain is the source of truth for membership.

---

## 3. Trust model

- **Theft** requires `t` of the `n` members of one epoch to sign a transaction
  the chain did not order. Every partial signature verifies against that
  member's public verifying share, so a participant in an unauthorized
  signature is identified and slashed.
- **Freeze** requires `n − t + 1` members to be unreachable.
- **Old shares.** A key-preserving reshare **retires nothing by itself.** See
  §9; this is the single most important correction to the earlier drafts.
- **Coordinator.** Any member. It can stall a session but cannot forge, and it
  cannot equivocate about the dealer set because the set is derived from chain
  state rather than proposed (§6).
- **Chain.** Penumbra consensus is trusted for what it already does: order
  transactions, finalize burns, hold custody state. A chain halt halts the
  bridge.
- **Deposit finality** is source-chain proof-of-work finality at depth `N`
  (§8), not a committee's assertion. Neither Bitcoin nor Zcash has absolute
  finality, so §8 states what happens when PoW later disagrees with a mint.
- **Privacy.** For Zcash, the prover set (§7.3) and any holder of the escrow
  incoming viewing key see every escrow note. Deposits and withdrawals are
  shielded to outside observers; they are not shielded from the bridge
  operators. This is a real cost and is stated rather than hidden.
- **Cryptographic maturity.** Nested FROST is not standard FROST; v2 is
  implemented and unaudited. Threshold Halo 2 proving is research. The
  weighted construction in `frost-spend::nested` pre-aggregates and is
  equivalent to *one* flat signer, not to `w` of them (§10).

### 3a. Lifecycle by governance

| Event | Trigger |
|---|---|
| Establish custody for an asset (parameters, threshold, value cap, depths, deadlines) | governance proposal; passing it starts the initial DKG |
| Epoch reshare | automatic at a chain-epoch boundary when the active set changed, or every `P` epochs |
| Withdrawal | automatic on a burn |
| Key rotation (fresh DKG + escrow migration) | automatic when departures since the last rotation reach `n − t + 1`; otherwise on the slow schedule |
| Prover-set rotation | automatic on the prover rotation schedule (§7.3) |
| Threshold, value cap, depth or deadline change | governance proposal |
| Freeze (no withdrawals, deposits still credited) | emergency proposal, or `t` members posting a freeze action |
| Deep-reorg resolution (§8) | governance proposal, bridge halted meanwhile |
| Recovery-path spend (§9a) | governance proposal after the timelock |

This mirrors IBC: a channel is established once and transfers are then
mechanical. Minted assets use the ICS20 voucher-denom convention so wallets,
the DEX and the explorer treat `pZEC` like any other bridged asset.

### 3b. Failure modes and their guards

| Way to lose funds or break things | Guard |
|---|---|
| Reshare lands members on different polynomials and old shares are deleted | old share kept until the chain activates the epoch; every member acks with its polynomial hash; all-members canary (§6.2) |
| Reshare stalls | previous epoch stays live; block-relative deadlines abort the round; retry gets a fresh epoch number |
| Signer signs a transaction the chain did not order | each signer verifies the transaction against chain state item by item (§8.2) and refuses on any mismatch; partials are attributable |
| Nonce reuse on a restored server | nonce state fsync'd before a partial is released; never snapshot-restored; fresh nonce stream per epoch (§6.4) |
| Mint without a real deposit | depth-`N` proof; total value cap relative to bonded stake |
| Source-chain reorg after a mint | §8.4: bridge halts, supply marked unbacked, governance resolves |
| Old-epoch quorum among ex-members | §9: escrow rotation, continuous note migration, `unbonding_delay` coupling, large `t`, prover/`nk` gate |
| Every member loses its share | Taproot timelocked recovery leaf on bitcoin (§9a); per-member offline share backups on both chains |
| Prover refuses to serve | rotating prover set, at least two members holding `nk` + `fvk` (§7.3) |
| Withdrawal stuck, underpaid or expired | fee bump through the same signing flow and the same checklist |

---

## 4. Chain component

A new `custody` component in `pd`, per asset. State:

```
CustodyState {
  asset:            pBTC | pZEC,
  group_key:        Y,                    // invariant across reshares
  key_generation:   g,                    // bumps on rotation (§9)
  epoch:            E,
  manifest_hash:    H,                    // hash of the epoch member set
  members:          [(validator_id, index)],
  polynomial:       F_E,                  // t points, public
  verifying_shares: [Y_j = F_E(j)],       // derived, cached
  status:           Active | Resharing{..} | Rotating{..} | Halted{reason},
  escrow_addrs:     [(generation, address, sweep_deadline)],
  prover_set:       [(validator_id, term_end)],   // Zcash only, §7.3
  fee_ledger:       { escrow_balance, wrapped_supply, paid_fees },
  withdrawals:      [WithdrawalJob],
}
```

Actions:

- `ReshareCommit { epoch, dealer_index, commitment }` — a dealer's Feldman
  commitment. `4 + 32·t` bytes.
- `ReshareAck { epoch, player_index, polynomial_hash, sig }` — a new member
  attests it derived its share and the public polynomial, signed under its
  verifying share `Y_j`, which proves it holds `s'_j` without revealing it.
- `EpochActivate { epoch, canary_signature }` — the group signature over a
  fixed test message produced by **all `n`** members; verified against `Y`.
- `WithdrawalProposed { job_ids, epoch, key_generation, tx_bytes, disclosure }`
  — §8.1.
- `WithdrawalSigned { job_id, epoch, key_generation, signature, tx_bytes }` —
  verified against `Y` and recorded.
- `Deposit { proof }` — §8.
- `Complaint { epoch, against_index, evidence }` — a missing or invalid
  sub-share, with the sealed message and decryption transcript, or an invalid
  partial signature. Leads to a penalty via the existing `Penalty` path.
  Complaints must be justified: evidence every node can re-check itself, not
  an assertion.

**The epoch is a consensus-checked action field, not a signing convention.**
Every action above that authorizes or consumes custody authority carries
`(epoch, key_generation)` explicitly, and `pd` rejects any value that is not
the currently active pair. This matters because it is the asymmetry between
the two legs: Penumbra actions are ours to define, so a superseded share set
can be refused by consensus outright. An Orchard `SpendAuthSig` is over a
sighash Zcash consensus fixes and has nowhere to put an epoch — so the Zcash
leg, and only the Zcash leg, has the retirement problem §9 addresses. The
earlier drafts described this as a general problem; it is not.

Burning `pZEC`/`pBTC` with a destination address creates a `WithdrawalJob`.
Jobs are batched per epoch window into one transaction per chain per window.

---

## 5. Membership

The member set for epoch `E` is the active validator set at the epoch boundary,
in the chain's own order, each member assigned a small integer index it keeps
for as long as it stays in the set. Indices are never reused within a key
generation. Integer identifiers are mandatory — `frost-spend` today derives ZF
identifiers from ed25519 keys, but the Lagrange math in `osst::reshare` assumes
small integers, so the custody DKG assigns `Identifier::try_from(u16)` and
keeps the ed25519 key as an authentication identity only.

Reshare at the boundary if the active set changed, and every `P` epochs anyway
if it did not (start with roughly monthly). If the active set is smaller than
`t + 1`, do not reshare: hold the current epoch, alert, let governance decide.
Signer-daemon liveness is tracked separately from validator liveness — a
validator whose daemon has not posted a heartbeat in two epochs is treated as
unreachable for dealer selection but stays a member. Jailed or tombstoned
validators leave at the next boundary; their old-epoch share is covered by §9.

---

## 6. Reshare protocol

Standard proactive secret sharing. Each dealer `i` in dealer set `S` re-shares
its share `s_i` with a fresh degree-`(t−1)` polynomial `f_i`, publishes Feldman
commitments `C_i`, and sends `f_i(j)` sealed to each new member `j`, which
computes `s'_j = Σ_{i∈S} λ_i^S · f_i(j)` and `F' = Σ_{i∈S} λ_i^S · C_i`, giving
verifying shares `Y_j = F'(j)` and the invariant `F'(0) = Y`.

Proven end to end for Zcash: shares dealt by ZF `frost-core` are reshared to a
different member set, which rebuilds ZF key packages and signs a rerandomized
RedPallas signature verifying under the *original* group key, while a stale
epoch-1 share mixed into an epoch-2 session fails aggregation with the culprit
identified. Two requirements came out of that: the Pallas backend must operate
in the Orchard spend-auth basepoint group (`OrchardSpendAuthCurve`), and
identifiers must be small integers (§5). Bitcoin is not yet proven the same
way; the `secp256kfun` port is a build-plan item.

### 6.1 Phases

| Phase | Who | Deadline | Effect |
|---|---|---|---|
| 0 Boundary | chain | `H_E` | status → `Resharing`, new member set fixed |
| 1 Commit | every reachable old member | `H_E + D1` | `ReshareCommit` on chain |
| 2 Dealer set | chain (deterministic) | `H_E + D1` | `S` = the `t_old` lowest indices with a valid commitment; recorded in state |
| 3 Distribute | each dealer in `S` | `H_E + D2` | sealed sub-share to each new member over the relay |
| 4 Aggregate + ack | each new member | `H_E + D2` | `ReshareAck` on chain |
| 5 Canary | all new members | `H_E + D3` | `EpochActivate` |
| 6 Activate | chain | on 5 | status → `Active`, epoch `E` live, `E−1` superseded |
| 7 Retire | every old member | `H_E + D4` | epoch `E−1` share and nonces deleted locally |

**The chain is the manifest.** Commitments are ordered by consensus and `S` is
computed from them, so there is no manifest to sign and no equivocation to
detect between signers. This is the piece that is hardest to get right
off-chain — an off-chain DKG needs an explicit echo round over the round-1
set to detect a dealer that sends different commitments to different
recipients — and it is free here.

Phase 7 is a **policy**, not a mechanism. See §9.

**Sub-share confidentiality.** Sub-shares are sealed per recipient with the
Noise_K scheme in `osst::sealed`, prologue bound to
`(chain_id, asset, epoch, attempt, polynomial-commitment hash)` so a sub-share
for one round cannot be replayed into another — including into a *retry of the
same epoch*, which is why `attempt` is in the prologue. Plaintext sub-shares
would let any observer recover every dealer's share whenever `n > t`.

### 6.2 Activation requires every member

The canary must be signed by all `n` new members, not a `t` subset. A `t`-of-`n`
signature only proves that `t` members landed on the same polynomial; with
6-of-11, six on one polynomial and five on another would pass and silently
leave a 6-of-6 group with no spare. The coordinator verifies each partial
against `Y_j` from the recorded `F'`, so a member on the wrong polynomial is
identified, and the chain requires a `ReshareAck` from every new member before
accepting `EpochActivate`.

### 6.3 Abort and retry

A dealer in `S` whose sub-share to some member is missing or invalid by `D2` is
the subject of a justified `Complaint`: the epoch aborts, the dealer is
excluded from `S`, and the retry runs as epoch `E+1` against the same member
set — the epoch counter is monotonic, not a block height. If fewer than
`t_old` old members commit by `D1`, no reshare happens and status returns to
`Active` on the previous epoch. With 6-of-11 and five members unreachable, `S`
has exactly six dealers and no tolerance for a faulting dealer; that is the
cost of the liveness choice.

### 6.4 Hard rules for signer daemons

1. **Never delete an epoch-`E−1` share until the chain has activated epoch
   `E`.** A botched reshare with old shares already gone is frozen funds.
2. **Every signing request names `(epoch, key_generation)`.** Signers refuse
   superseded epochs and epochs they have not activated. Nonce streams are
   opened fresh per epoch.
3. **Nonce state is fsync'd before a partial signature is released and is
   never restored from a VM snapshot or filesystem rollback.** Two responses
   under one nonce leak the share by elementary algebra. Snapshots are
   operational routine, which makes this the failure most likely to happen in
   practice. The spent-round store is keyed by
   `(key_generation, epoch, session_id, holder_index)`.
4. **The group public key `Y` comes from the local key package**, never from a
   coordinator's request.

---

## 7. The Zcash leg

### 7.1 Escrow and deposits

The escrow is an Orchard address derived from the threshold-held `ask` and the
jointly generated `nk`. Deposits are detected by trial-decrypting Orchard
outputs with the escrow **incoming** viewing key — `ivk`, not `nk` — so
deposit detection needs no spending-adjacent material.

The depositor names their Penumbra destination in the Orchard memo. A Penumbra
address is 80 bytes and a memo is 512, so it fits with room for a version tag
and routing metadata. The encoding is the ZIP-302 structured-memo scheme in
`frost-spend::memo_codec`: a 4-byte header (`0xFF` arbitrary-data tag, magic,
type, sequence) leaving 508 bytes of payload, with a fragmented form for
larger payloads. A ZIP-321 payment URI is the natural way to hand a user a
pre-filled deposit request; the Zafu wallet consumes the same stack.

**Dust and bad memos.** A deposit with no memo, a malformed memo, or an
unparseable Penumbra address is credited to a hold account rather than minted
or refunded — a shielded deposit does not necessarily reveal a return address,
so refunds are not always possible. Claiming from the hold account requires a
proof of deposit (knowledge of the note's `rseed`). Deposits below a
governance-set dust threshold are held and swept, never minted.

### 7.2 Spend authorization

An Orchard spend authorization signs the ZIP-244 signature digest with
`rsk = ask + α`, verified against `rk = ak + [α]·G`, where `α` is a public
per-action randomizer chosen by the transaction builder. The threshold group
produces this signature over the sighash the prover published, using
`frost-spend`'s RedPallas path with the per-action `alpha` binding it already
performs.

**Rerandomization does not retire shares.** `rsk = ask + α` is *linear* in `α`,
and `α` is public. A holder of any share of `ask` can sign under any `α`
whatsoever; there is no derivation in which an old share "fails" for a new
randomizer. Rerandomization is an unlinkability mechanism, not an
authorization mechanism, and any scheme that proposes a group-chosen `α` per
epoch as a retirement mechanism should be discarded.

### 7.3 The prover set

An Orchard spend needs a Halo 2 proof as well as a signature, and proving in
MPC is not a solved engineering problem. The split that works today:

A **prover** holds the escrow's nullifier key `nk` and full viewing key `fvk`
— enough to see the escrow's notes and construct valid proofs, but *not*
enough to spend, because spending additionally requires the spend-authorization
signature the threshold group controls. The prover assembles the withdrawal
transaction off-chain, produces the action proofs, and publishes the result
(§8.1). A prover that lies produces a sighash nobody signs.

**`nk` is not given to every member.** An earlier draft did give `nk` to the
whole set so that all members could scan. That discards a second factor: a
stale quorum holding old `ask` shares still cannot spend, because the Halo 2
proof witness requires `nk` and the note witness. The prover/`nk` gate is
therefore load-bearing for share retirement, not merely for liveness, and it
is kept separate from `ask` custody.

The prover set is a rotating subset of the validators — at least two at any
time so that a single refusal is not a chokepoint, with staggered terms
recorded in `prover_set` and rotated on a governance-set schedule. Validators
outside the prover set scan for deposits with `ivk` only. This concentrates
*viewing* power in a named, rotating, minimal set instead of spreading it to
everyone; it does not remove the privacy cost, and threshold proving is the
only thing that would (§10).

### 7.4 Sealed DKG and nested positions

The initial DKG and every reshare use `osst`'s sealed interleaved Feldman VSS
over Pallas: each node deals in `t` parallel ceremonies so the group holds
Shamir shares of each coefficient and no node learns a coefficient. Round 1
carries a Schnorr proof of knowledge of the constant term, verified before the
commitment is recorded. Round 2 is point-to-point: each recipient gets its own
`Noise_K_25519_ChaChaPoly_BLAKE2s` package, and opening runs the Feldman check
against a commitment digest carried inside the sealed plaintext. Noise_K gives
sender authentication and payload security but **no forward secrecy** —
compromise of one recipient's X25519 static decrypts every sub-share ever sent
to it from recorded traffic — so the key generation and epoch go into the
X25519 derivation info, bounding the exposure window to one epoch.

A validator may hold its single outer share as a nested FROST v2 position
across its own hosts. Under v2 the coordinator publishes the whole outer round
and each inner holder recomputes the binding factor, challenge and Lagrange
coefficient for itself from the package, so a coordinator can assert neither a
challenge nor a message; the position's response is bit-for-bit what a flat
signer holding the same key and nonce would produce, which is why the chain
component can be blind to it. Implemented and unaudited (§10).

## 7a. The Bitcoin leg

The escrow output is Taproot with the FROST key on the key path. Deposits are
proven by SPV against a header chain `pd` tracks; who submits headers and at
what cost is open (§11). The withdrawal check is the PSBT owned-input and
change-path check `frostsnap_core` already performs, plus the applicable items
of §8.2. `frostsnap_core`'s `KeyId` is invariant across reshares and
`AccessStructureId` changes per epoch, which is the right shape; its
fingerprint-matching restoration flow will not hold for reshared polynomials
and needs a per-epoch path.

---

## 8. Deposits, withdrawals and finality

### 8.1 Deposit finality

A deposit mints only after `N` confirmations on the source chain, where `N` is
a governance parameter with initial values of **60 blocks for Zcash** (~75
minutes) and **12 blocks for Bitcoin** (~2 hours). `pd` verifies proof of work
and difficulty adjustment on a submitted header chain, exactly as the IBC
light client does for a Tendermint chain, and treats a header as eligible at
depth `N`.

### 8.2 Withdrawal verification checklist

Each validator receives the **full transaction bytes** and a disclosure bundle
in the on-chain `WithdrawalProposed` action posted by the prover (Zcash) or the
epoch coordinator (Bitcoin). On-chain delivery is deliberate: it gives every
validator the same bytes, makes the proposal attributable, and removes the
relay as a place where two validators can be shown different transactions. The
signer fetches the action from its own `pd`, never from the coordinator.

Each validator then verifies locally and **refuses to sign on any failure**:

1. The transaction's outputs correspond one-to-one with the `WithdrawalJob`s
   named by `job_ids`, in destination and in value.
2. Every output's note plaintext is disclosed, and `cmx` recomputed from it
   matches the action — this pins recipient, value and memo without needing
   `ovk`.
3. Per Orchard action, `alpha` and `rcv` are disclosed by the builder and
   check out.
4. The change output pays back to the **current** escrow address for the
   current `key_generation`, and its value is `Σv_in − Σv_out(payouts) − fee`.
5. There are **no outputs beyond** the enumerated payouts and the single change
   output; no transparent bundle; no Sapling bundle; no actions beyond those
   enumerated.
6. Each spend's claimed escrow note is in the validator's own `ivk`-decrypted
   set, with `cv_net` recomputed from `(v_in − v_out, rcv)` — this pins the
   spent value without needing `nk`.
7. The anchor is a locally-known Zcash anchor at depth ≥ `N`.
8. `Σv_in − Σv_out` equals the declared fee, and the fee is within a ZIP-317
   bound for the transaction's action count (Bitcoin: within a governance-set
   sat/vB band).
9. The expiry height is set and is sane — in the future, and no further ahead
   than the batching window plus a margin.
10. `(epoch, key_generation)` in the proposal equal the chain's active pair.
11. The sighash is **recomputed from those bytes** by the validator, and that
    recomputed sighash is the only thing signed. A sighash supplied by anyone
    else is never signed.

Signing then runs over the relay: pre-shared nonce commitments, one round of
partial signatures, coordinator aggregates. Partials are verified against `Y_j`
and an invalid one is a `Complaint`. The coordinator broadcasts and posts
`WithdrawalSigned`; the chain marks jobs complete once the transaction is seen
at depth `N` through the same header path.

A stuck or expired transaction is replaced by fee bump (RBF on Bitcoin, expiry
rebuild on Zcash) through the same flow, with the same checklist.

### 8.3 Fees, and the supply/backing ledger

The withdrawal transaction pays its own source-chain fee **out of escrow**.
Wrapped supply therefore drifts from escrow backing on every withdrawal unless
it is accounted, so it is accounted: the burn action collects a fee estimate
up front in `pZEC`/`pBTC`, that estimate is burned along with the payout, and
`fee_ledger` records `escrow_balance`, `wrapped_supply` and cumulative
`paid_fees`. The invariant the chain checks is

```
escrow_balance == wrapped_supply + reserve − paid_fees_not_yet_burned
```

where `reserve` is a governance-set buffer for fee estimation error. A
withdrawal whose actual fee exceeds the collected estimate draws on `reserve`;
a shortfall in `reserve` pauses withdrawals rather than silently unbacking
supply.

### 8.4 Reorg after a mint

Neither chain has finality, so this needs a rule rather than a parameter.

- A reorg **shallower than `N`** that unwinds an unconfirmed deposit is
  ordinary: the deposit never reached depth `N` and was never minted.
- A reorg **deeper than `N`** that unwinds an already-minted deposit **halts
  the bridge**: `status → Halted`, no further mints, no further withdrawals,
  the affected mint is flagged in `fee_ledger` as unbacked supply, and the
  resolution — burn from a reserve, socialize, or accept — is a governance
  proposal. The mint itself is **not** reversed automatically; the wrapped
  asset has by then moved, and unwinding it inside a shielded pool is not
  possible.
- The same rule applies to a reorg that unwinds a confirmed *withdrawal*: the
  job returns to pending and is re-signed against the current escrow state,
  which is safe because the spent notes are still unspent on the reorganized
  chain.

Withdrawals are batched per epoch window, which gives a reorg a window to
surface before funds leave.

---

## 9. Key rotation and old shares

**This section replaces the earlier drafts' treatment, which was wrong.**
Three sentences in circulation are false and are withdrawn:

- "Old shares become useless" after a reshare — **false.**
- A development step that verifies "the old shares cannot spend" after a
  reshare — **it cannot be verified, because it is not true.**
- Any claim that an epoch-bound signing context retires shares for an Orchard
  spend — it does not reach a `SpendAuthSig`.

A key-preserving reshare re-randomizes the polynomial while preserving `f(0)`.
A departed member holding an epoch-`e` share still holds a valid share of the
same secret, forever. Shares from different epochs do not interpolate with each
other, so the requirement is per-epoch, and the honest statement of the
invariant is:

> for every past epoch `e`, the number of departed-or-compromised holders of
> epoch-`e` shares must remain below `t`.

Cumulative churn violates this eventually and unconditionally. Deleting old
shares (phase 7, §6.1) is a **policy**, not a mechanism: nothing on-chain can
verify it happened.

**The design therefore accepts escrow address rotation as a protocol
operation.** This is the only mechanism that actually retires shares, because
it retires the key. The five controls, adopted together:

1. **The escrow address rotates.** It is not fixed and was never safely
   fixable. The current address for each asset is published on-chain in
   `escrow_addrs`, and deposit-address lookup is a protocol operation that
   wallets perform — which turns the fixed-address requirement into a UX
   problem, where it belongs. Deposits arriving at a superseded address are
   swept in the next withdrawal batch for a grace period recorded in
   `escrow_addrs`; after the grace period the old address is dropped from the
   watcher.
2. **Escrow is held in many small notes, migrated continuously.** Rather than
   a flag-day sweep, each withdrawal batch also migrates a bounded number of
   notes from superseded generations to the current group key. This bounds the
   exposure of any one rotation to the notes not yet moved, and fits how a
   bridge already spends. It does not change the security argument; it makes
   rotation affordable.
3. **Rotate on the `n − t + 1` departure trigger.** Run a fresh DKG (new `Y`,
   `key_generation + 1`) whenever the number of members departed since the last
   rotation reaches `n − t + 1` — with 6-of-11, six departures, the point at
   which some past epoch could hold a full quorum among ex-members — and in any
   case on a slow schedule, quarterly at first. With a stable set this fires
   rarely.
4. **Couple `unbonding_delay` to the rotation period.** Require
   `unbonding_delay` to be at least the maximum time between a member's
   departure and the rotation that makes its old share worthless. Then a
   validator that leaves and later colludes with an old-epoch quorum is still
   bonded and slashable when it matters. This couples a staking parameter to a
   custody parameter and is a governance-set value.
5. **Keep `t` large, and keep the prover/`nk` gate as a second factor.** A
   large `t` raises the collusion bar for every past epoch simultaneously; it
   does not bound the number of past epochs, so it is necessary and not
   sufficient. The prover gate (§7.3) is the second factor: a stale `ask`
   quorum cannot produce the Halo 2 proof without `nk`.

With these, the escrow's safety no longer rests entirely on unverifiable
operational properties. It rests on rotation, which is a construction.

### 9a. Recovery path on bitcoin

The Bitcoin custody output is Taproot with the FROST key on the key path and
one hidden script leaf as a fallback: after a long relative timelock (start
with six months) it can be spent by a **recovery key**. The leaf is never
revealed unless used, and every withdrawal and migration spends via the key
path, resetting the timelock on the change output, so the fallback only becomes
live if the validator set has been unable to move funds for the whole period.
Open choice for governance: a governance-held recovery key (slower, safer) or a
smaller `k`-of-`n` of the validators' individual keys (does not depend on the
chain being alive).

**Orchard has no script path.** On Zcash, per-member offline share backups are
the only recovery, which is a further reason to keep `t` comfortably below `n`
and to rotate.

---

## 10. Status: what exists

| Piece | State |
|---|---|
| `osst` (frostito) | **0.4.0** (`bf30136`): nested FROST v2, DKG with proofs of knowledge, sealed round-2 delivery, epoch-bound `SigningContext`, key-preserving reshare, RedPallas. Unaudited. **0.5.0 in progress**, carrying the maintainer-review blockers: length-prefixed contribution-signature message, deprecated plaintext `SubShare::to_bytes`, an echo-round digest helper for dealer equivocation, `active_indices` validation in `inner_sign_v2`, precommit enforcement. |
| `narsild` sidecar | Draft, `penumbrafi/penumbra` **PR #31**. Sealed DKG with PoKs and complaints, roster, two-round nested FROST v2 signing bound to epoch and manifest, key packages at mode 0600. **Not mergeable as-is**: the 2026-09-21 maintainer review lists blockers (i–ix) including secret shares served over an unauthenticated `GET /dkg/status`, an unauthenticated signing oracle, unauthenticated DKG initiation that truncates the key package, `Y` taken from the request, and no durable spent-nonce store. The cryptographic core is in better shape than the HTTP surface. |
| Token factory | Component, protos, `pcli` support, governance-gated and dormant by default, app version 13. Open for review as `feature/token-factory` (**PR #2**). |
| `zcli` / `frost-spend` | Pallas DKG, sealed round 2, PCZT signing, ZIP-302 memo codec (typed and fragmented, plus DKG-over-memo transport). `master` at `d4243ad` (PR #17) adopted osst 0.4.0 and closed the weighted findings W-1..W-4: `frostito_sign_v2` now takes the approved message and derives the outer context only via `InnerSigningParamsV2::from_outer`; `WeightedRoster` is the sole source of weight, with `max_weight < threshold`, non-zero, non-overlapping allocations and checked `u64` sums. The weighted path still pre-aggregates — the nested position is equivalent to **one** flat outer signer, not to `w` of them — and has no non-test caller. Weighting stays deferred for v1. |
| Zafu wallet | Consumes the same memo and FROST stack; the depositor-side UX for Zcash. |
| Reshare, proven | `osst::reshare` round-trips ZF-dealt Pallas shares to a different member set and signs under the original group key, with stale-epoch shares rejected and attributed. |

Missing: the Zcash header light client inside `pd`; the `custody` component
itself; deposit detection, mint/burn wiring and withdrawal events; reshare
driven from Penumbra epoch transitions; a durable spent-round store; the
prover role and Orchard transaction construction; slashing and timeout rules
for non-signers; the `secp256kfun` reshare port; external review of nested
FROST v2 and of the bridge component.

---

## 11. Build plan

Ordered, and the order matters: everything before step 5 runs with
command-line tools against testnets and touches no consensus code.

1. **`zcli` + `pcli` first.** Establish the escrow key with a local `osst` DKG,
   derive the Orchard escrow address, and prove the round trip by hand: send
   testnet ZEC with a `zcli`-encoded ZIP-302 memo, have `zcli` build and prove
   the Orchard spend, produce the threshold spend-authorization signature, and
   broadcast. Independently, mint and burn the wrapped denom on a devnet with
   `pcli` against the token-factory mint capability. No chain changes, no
   daemon, no relay — this validates the memo scheme, the
   `OrchardSpendAuthCurve` backend, the integer identifiers and the PCZT
   sighash path, and it is cheap to redo.
2. **Watcher.** A standalone process that trial-decrypts escrow outputs with
   `ivk`, applies the dust and bad-memo policy, and reports the credits a
   bridge component would make. Still no chain changes.
3. **Withdrawal verification harness.** §8.2 as a library with the checklist as
   a test matrix: a proposal that adds an output, moves the change, inflates
   the fee, uses a stale anchor, or supplies a sighash that does not match its
   bytes must be refused, each with a named error.
4. **Signer sidecar on Zcash regtest**, 3-of-5, on a local devnet. Matrix: DKG;
   deposit; withdraw; evict one, reshare, withdraw; re-admit; dealer faults
   after `D1`, abort, retry; superseded-epoch request refused; daemon killed
   mid-round restarts without nonce reuse; snapshot-restored signer refuses to
   sign.
5. **Chain component skeleton** with `CustodyState`, the reshare actions, the
   deterministic dealer set and the epoch/key-generation consensus checks. No
   signing. Unit-tested against the phase table.
6. **Zcash testnet with the real eleven**, small TAZ balance, four epochs with
   an eviction, a re-admission and one rotation — including continuous note
   migration and the grace-period sweep of the superseded address — then the
   `unbonding_delay` coupling as a governance parameter.
7. **Bitcoin.** Port reshare to `secp256kfun`; `frostsnap_core` sidecar
   backend; signet run; deposit-proof path.
8. **Mainnet** with a capped total value, raised over time.

A rehearsal harness is a prerequisite for step 5: five `pd` + CometBFT
validators under `process-compose`, one `zebrad` regtest, one `bitcoind`
regtest, one `frostd` relay, five `pd custody-signer` processes, and a scenario
driver that scripts the whole lifecycle including the chain upgrade that
introduces the component. Every row of §3b is one scenario in that driver, and
the driver is what CI runs.

---

## 12. Open questions

- **Threshold proving.** Can the Halo 2 action proof be produced without a
  single party holding `nk` + `fvk`? Until it can, the prover set is the
  privacy weak point and the `nk` gate is doing double duty as a security
  factor and a privacy cost.
- **Bitcoin deposit proofs.** SPV inside `pd` needs someone to submit headers
  and a rule for reorgs. The weaker, simpler v1 alternative is signed
  attestations from `t` validators' own Bitcoin nodes.
- **Batching window and fee policy.** Per-epoch batching suits a quiet bridge;
  a busy one wants shorter windows and a different fee-estimate model.
- **Coordinator and prover selection.** Lowest heartbeating index rotating per
  epoch is proposed for the coordinator; the prover set needs an explicit
  selection rule, not just a rotation schedule.
- **Unbonding delay** value, and **minimum member count** — with eleven,
  `t + 1 = 7` is the floor at which reshares stop; below that, hold or lower
  `t` by governance?
- **Penumbra-side privacy.** Members' partial signatures are attributable on
  Penumbra by design, for slashing. The earlier OSST design optimized for the
  opposite; confirm the trade is acceptable.
- **Audit scope.** Nested FROST v2, the sealed DKG round, the reshare
  protocol, the `custody` component, and the interaction between them. The
  composition is where the interesting failures are.
