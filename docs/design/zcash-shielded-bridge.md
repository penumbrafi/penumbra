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

- **Signed roster.** Every node has a static X25519 identity and is configured
  with the same `index → (URL, public key)` map. The roster's fingerprint —
  SHA-256 over the sorted, length-prefixed `(index, pubkey, url)` triples —
  is what the rest of the protocol is bound to: it derives the DKG session id,
  which goes into the sealing prologue, and it is the `manifest_hash` of every
  signing context. Nodes that disagree about the membership, or about where a
  member lives, cannot complete a ceremony together.
- **Sealed DKG.** Distributed interleaved Feldman VSS over Pallas — the curve
  Orchard uses for spend authorization. Each node acts as a dealer in `outer_t`
  parallel ceremonies so the group ends up holding Shamir shares of each
  coefficient of the outer polynomial; no node learns a coefficient. Round 1
  carries a Schnorr proof of knowledge of the constant term, verified before
  the commitment is recorded. Round 2 is confidential and point-to-point: each
  recipient gets its own `Noise_K_25519_ChaChaPoly_BLAKE2s` package and no
  other, and opening runs the Feldman check. Any complaint aborts the ceremony.
- **Nested FROST v2 signing.** The validator set occupies a single position in
  an outer FROST scheme, and that position is itself a threshold group. This is
  what lets the outer scheme stay small while the inner group is the whole
  stake-weighted validator set. Under v2 the coordinator publishes the whole
  outer round — every commitment, the group key, the nested index — and each
  node recomputes the binding factor, challenge and Lagrange coefficient for
  itself. A coordinator cannot assert a challenge, and cannot obtain a
  signature over a payload the inner group did not see.
- **Epoch-bound signing context.** The bytes signed are
  `SigningContext { epoch, manifest_hash, message }.encode()`, with the epoch
  and manifest taken from each node's own key package rather than from the
  request. A node holding epoch-`e` shares refuses a round built for `e+1`.
  Today the epoch is the DKG generation counter; when reshare lands it becomes
  the reshare epoch, which is what makes a key-preserving reshare an actual
  rotation. The caveat is that this binds only *osst-aware* verifiers —
  custody authorization, escrow release, internal attestations. It does not
  reach an Orchard `SpendAuthSig` over a consensus-fixed sighash, where there
  is nowhere to put the epoch; retiring shares there needs an on-chain
  rotation to a new group key, which is exactly what the fixed escrow address
  is designed to avoid. That tension is unresolved and is called out in §6.
- **Key-preserving reshare each epoch.** At each Penumbra epoch boundary the
  share set is reshared to the new validator set, weighted by stake. Old shares
  become useless; the group key, and hence the escrow address, is unchanged.
  Not implemented yet.

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
- **Cryptographic maturity.** Nested FROST is not standard FROST. `osst`'s
  `SECURITY-nested-frost.md` documents an outer-binding gap in the v1 nested
  construction — the inner binding factor omitted the outer commitment set,
  which collapsed FROST's ROS resistance for that position — and a v2
  construction that restores it. osst 0.4.0 removed v1 from the default build
  (finding R-1) and `narsild` is on v2. v2 is implemented and unaudited.
  Threshold proving is research.
- **Review findings already closed.** `SECURITY-REVIEW-2026-09.md` found two
  issues in `narsild` itself: round-2 sub-shares were plaintext scalars
  broadcast to every peer (D-1, Critical — a single participant could
  reconstruct the group key), and nothing bound a sub-share to the commitment
  it was checked against (D-2). Both are fixed; the key packages produced
  before the fix are unusable and `narsild` refuses to load them.

## 4. What exists today

| Piece | State |
| --- | --- |
| `narsild` sidecar | Prototype: sealed DKG with proofs of knowledge and complaints, signed roster, two-round nested FROST v2 signing bound to an epoch and manifest, key packages persisted at mode 0600. No reshare, no stake weighting, no authentication on the HTTP endpoints themselves. Branch `narsild`. |
| Token factory | Component, protos, pcli support, governance-gated and dormant by default, app version 13. Open for review as `feature/token-factory` (PR #2). |
| `osst` (frostito) | Nested FROST v2, DKG with proofs of knowledge, sealed round-2 delivery (`osst::sealed`), epoch-bound `SigningContext`, key-preserving proactive reshare, RedPallas. Canonical home is `github.com/penumbrafi/frostito`; `narsild` pins **0.4.0** (rev `bf30136`), the security release for `SECURITY-REVIEW-2026-09.md`. Unaudited. |
| ZIP-302 memo codec | Implemented in `zcli`'s `frost-spend::memo_codec`, with typed and fragmented memos and DKG-over-memo transport. |
| Zafu wallet | Consumes the same memo and FROST stack; the natural depositor-side UX. |

Missing:

- Zcash header light client inside `pd`.
- Bridge component: deposit detection, confirmation depth, mint/burn wiring,
  withdrawal events.
- Reshare driven from Penumbra epoch transitions and stake weights — until it
  exists the signing context's epoch is only the DKG generation counter, so it
  distinguishes one key from the next rather than one share set from the next
  under a preserved key.
- A durable spent-round store keyed by `(epoch, session_id, holder_index)`, so
  a node restored from a snapshot cannot be made to reuse nonces. Open as
  `osst` finding A-3, and the deployment's to build.
- Authentication of the `narsild` HTTP endpoints. The roster authenticates the
  DKG's secret round and the signing context, not the transport.
- Stake-weighted inner shares: today every validator holds one share index.
  `osst`'s weighted nested FROST is deferred to its own review.
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
- **Retiring shares for a consensus-fixed signature.** The epoch-bound signing
  context stops an old quorum authorizing *narsild's own* messages, but an
  Orchard `SpendAuthSig` is over a sighash Zcash consensus fixes, with nowhere
  to put an epoch. A pre-rotation quorum that kept its shares can still produce
  a valid spend authorization. The fixed escrow address is the whole premise of
  §1, so "rotate the group key" is not available. Deleting old shares is a
  policy, not a mechanism; this needs a real answer.
- **Audit scope.** Nested FROST v2, the sealed DKG round, the reshare protocol,
  the bridge component, and the interaction between them — the composition is
  where the interesting failures usually are.
