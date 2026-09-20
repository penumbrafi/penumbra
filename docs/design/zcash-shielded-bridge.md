# A shielded Penumbra ↔ Zcash bridge

Status: design sketch. Nothing described here is implemented end to end, and
none of the cryptography involved has been audited.

## 1. Goal

Move ZEC into Penumbra and back out again without either leg being
transparent.

The Penumbra validator set collectively custodies an **Orchard escrow address**
on Zcash. ZEC sent to that address is credited on Penumbra as a wrapped asset
minted by the token-factory component; burning the wrapped asset on Penumbra
releases the corresponding ZEC from the escrow. Both legs are shielded: the
Zcash side is an Orchard note, the Penumbra side is an ordinary shielded note.

The property that makes this practical is that the escrow address **never
changes**. The escrow key is a threshold key held by the validator set, and
proactive resharing is key-preserving — the group public key `Y = g^s` is an
invariant across reshares — so validators can join and leave, and shares can be
rotated every epoch, while the address users deposit to stays the same. No
migration transaction, no address rotation, no stranded deposits.

## 2. Architecture

Two halves: a consensus-side component in `pd`, and an off-chain signing
sidecar per validator.

### 2.1 Consensus side (`pd`)

**Zcash light client.** A Zcash block-header chain verified inside Penumbra
consensus, following the same shape as the existing IBC light client: headers
are submitted by relayers, the component checks proof-of-work and difficulty
adjustment, and treats a header as final after a confirmation depth. Deposit
finality is therefore Zcash PoW finality, not a committee's assertion.

**Deposit detection.** The bridge holds an *incoming viewing key* for the
escrow. Orchard outputs paid to the escrow are trial-decrypted with it. The
depositor names their Penumbra destination in the Orchard memo field: a
Penumbra address is 80 bytes and an Orchard memo is 512 bytes, so it fits
comfortably in a single memo with room for a version tag and routing metadata.
The memo is encoded with the ZIP-302 structured-memo scheme already implemented
in `zcli`'s `frost-spend::memo_codec` — a 4-byte header (`0xFF` arbitrary-data
tag, magic byte, type byte, sequence byte) leaving 508 bytes of payload, with a
fragmented form for larger payloads. A ZIP-321 payment URI is the natural way
to hand a user a pre-filled deposit request.

**Mint.** A verified deposit at sufficient depth produces a mint of the wrapped
asset through the token-factory component. The wrapped denom is minted against
a mint capability the bridge owns; supply is therefore auditable on Penumbra
and comparable against the escrow balance observable on Zcash.

**Burn → withdrawal.** A burn of the wrapped asset carrying a Zcash destination
emits a withdrawal event. The event, not any off-chain message, is the
authorization: it is what the validators check before they sign.

### 2.2 Custody side (`narsild`)

`narsild` runs next to each validator and speaks a small JSON HTTP protocol to
its peers.

- **DKG.** Distributed interleaved Feldman VSS over Pallas — the curve Orchard
  uses for spend authorization. Each node acts as a dealer in `outer_t`
  parallel ceremonies so the group ends up holding Shamir shares of each
  coefficient of the outer polynomial; no node learns a coefficient. Validators
  who miss the round-1 window are excluded from that ceremony rather than
  aborting it.
- **Nested FROST signing.** The validator set occupies a single position in an
  outer FROST scheme, and that position is itself a threshold group. This is
  what lets the outer scheme stay small while the inner group is the whole
  stake-weighted validator set. Signing is two rounds: nonce commitments, then
  signature shares aggregated into `z_nested` given the outer challenge and
  Lagrange coefficient.
- **Epoch-bound signing context.** Signing sessions should be bound to a
  Penumbra epoch and to the specific withdrawal event, so a signature produced
  for one epoch's validator set cannot be replayed into another.
- **Key-preserving reshare each epoch.** At each Penumbra epoch boundary the
  share set is reshared to the new validator set, weighted by stake. Old shares
  become useless; the group key, and hence the escrow address, is unchanged.

### 2.3 Building the Orchard transaction

A threshold signature authorizes an Orchard spend, but an Orchard spend also
needs a Halo 2 proof, and proving in MPC is not a solved engineering problem.
The split that works today:

A **prover** holds the escrow's nullifier key and full viewing key — enough to
see the escrow's notes and construct valid proofs, but *not* enough to spend,
because spending additionally requires the spend-authorization signature the
threshold group controls. The prover assembles the withdrawal transaction
off-chain, produces the action proofs, and publishes the resulting sighash.
Each validator independently checks that the transaction matches the
withdrawal event emitted on Penumbra — destination, amount, escrow change —
and only then contributes its FROST share. A prover that lies produces a
sighash nobody signs.

This concentrates *viewing* power, not spending power. It is a real privacy
cost and should be stated plainly rather than hidden.

## 3. Trust model

- **Safety.** Funds are safe unless a coalition holding more than the
  stake-weighted threshold of shares colludes. That is the same trust boundary
  as Penumbra consensus itself, which is the point: the bridge does not
  introduce a new, smaller committee.
- **Liveness.** Withdrawals require a threshold of validators to be online and
  running `narsild`. Non-signing needs an economic answer (see §5).
- **Deposit finality** follows Zcash proof of work through the light client,
  with a confirmation depth chosen against reorg risk.
- **Privacy.** Validators acting as provers, and any party holding the escrow
  incoming viewing key, see the escrow's notes. Deposits and withdrawals are
  shielded to outside observers; they are not shielded from the bridge
  operators.
- **Cryptographic maturity.** Nested FROST is not standard FROST. The `osst`
  security note documents an outer-binding gap in the v1 nested construction —
  the inner binding factor omitted the outer commitment set, which collapsed
  FROST's ROS resistance for that position — and a v2 construction that
  restores it. v2 is implemented and unaudited. Threshold proving is research.

## 4. What exists today

| Piece | State |
| --- | --- |
| `narsild` sidecar | Prototype: DKG, two-round nested signing, peer broadcast, HTTP API. No persistence, no auth, no epoch binding. Branch `narsild`. |
| Token factory | Component, protos, pcli support, governance-gated and dormant by default, app version 13. Open for review as `feature/token-factory` (PR #2). |
| `osst` (frostito) | Nested FROST v2, DKG, key-preserving proactive reshare, RedPallas. Canonical home is `github.com/penumbrafi/frostito` (crate `osst` 0.2.0, the rev `narsild` pins); the copies vendored in `zcli` and `zk.poker` are being removed. Unaudited. |
| ZIP-302 memo codec | Implemented in `zcli`'s `frost-spend::memo_codec`, with typed and fragmented memos and DKG-over-memo transport. |
| Zafu wallet | Consumes the same memo and FROST stack; the natural depositor-side UX. |

Missing:

- Zcash header light client inside `pd`.
- Bridge component: deposit detection, confirmation depth, mint/burn wiring,
  withdrawal events.
- Epoch binding in the `narsild` signing context, and share persistence.
- Reshare driven from Penumbra epoch transitions and stake weights.
- Orchard transaction construction and proving; the prover role.
- Slashing and timeout rules for validators that do not sign.
- External review of nested FROST v2 and of the bridge component.

## 5. Development plan

The bridge can be exercised with command-line tools long before any of it
touches consensus. Each step is a real test with real funds on testnet.

1. **Local DKG.** Run `narsild` on several nodes, complete a ceremony, derive
   the group key, and turn it into an Orchard escrow address.
2. **Deposit.** Send testnet ZEC to the escrow with a `zcli`-encoded memo
   carrying a Penumbra address.
3. **Watcher.** A standalone watcher trial-decrypts escrow outputs with the
   incoming viewing key and reports the credit that a bridge component would
   make. No chain changes yet.
4. **Mint.** Mint the wrapped asset on a devnet with `pcli`, against the
   token-factory mint capability.
5. **Withdrawal round trip.** Burn the wrapped asset; have `zcli` build and
   prove the Orchard spend; have `narsild` produce the threshold
   spend-authorization signature; broadcast on Zcash testnet.
6. **Reshare under load.** With funds sitting in escrow, reshare to a different
   validator set. Verify the escrow address is unchanged, that the new set can
   spend, and that the old shares cannot.

Only then: fold the watcher into a `pd` bridge component, add the Zcash light
client, and make mint and burn consensus actions.

## 6. Open questions

- **Threshold proving.** Can the Halo 2 action proof be produced without a
  single party holding the full viewing key? Until it can, the prover role is
  the privacy weak point. Rotating the prover per withdrawal spreads the
  exposure without removing it.
- **Prover selection.** Elected? Rotating? Whoever is first to publish a
  sighash that a threshold will sign?
- **Bad deposits.** ZEC arriving with no memo, a malformed memo, or an
  unparseable Penumbra address. Refunds require knowing a Zcash return address,
  which a shielded deposit does not necessarily reveal. A hold-and-claim path
  with a proof of deposit is the likely answer.
- **Slashing.** Distinguishing a validator that will not sign from one that
  cannot, and designing a penalty that does not punish honest downtime.
- **Confirmation depth** on the Zcash side, and behaviour under a deep reorg
  that unwinds an already-minted deposit.
- **Audit scope.** Nested FROST v2, the reshare protocol, the bridge
  component, and the interaction between them — the composition is where the
  interesting failures usually are.
