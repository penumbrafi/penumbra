/-
  ╔════════════════════════════════════════════════════════════════════════════════════════╗
  ║  DRAFT FOR CRYPTOGRAPHER REVIEW — SKELETON, NOT A PROOF.                               ║
  ║  Every theorem below is `sorry`. Every structure field and every clause of `ValueSpec` ║
  ║  is a *transcription* of the arkworks R1CS code by a non-cryptographer and MUST be     ║
  ║  checked against the Rust before anything downstream is trusted. `-- REVIEW:` marks    ║
  ║  the places where the transcription is least certain.                                  ║
  ╚════════════════════════════════════════════════════════════════════════════════════════╝

  DelegatorVote circuit — value-commitment soundness frame (SKELETON, no proof).

  Structure mirrored from zcash/ironwood (Apache-2.0 / MIT):
    Zcash/Security/Ledger/Statement.lean  — public instance vs. private witness, statement as Prop
    Zcash/Security/Ledger/Value.lean      — `ValueShape` (Pedersen shape with abstract bases)
    Zcash/Circuits/Action/Spec.lean       — the circuit-facing `ActionSpec` conjunct list, one
                                            clause per in-circuit `enforce_equal` (+ range clause).
  Ironwood has no governance circuit; only the style is mirrored. Within THIS project the file
  mirrors `Penumbra/Circuits/Spend/Basic.lean` (same `CommitShape`, `Witness`, `Satisfies`,
  `ValueSpec`, `*_valueAccounted` shape — names kept identical so a later hoist of the shared
  record into `Penumbra/Circuits/ValueCommit` is a mechanical move) and borrows the
  "verifier recomputes the public input from the transparent body" idiom (`publicOf`) from
  `Penumbra/Circuits/Swap/Basic.lean`.

  Real circuit (source of truth, arkworks R1CS over BLS12-377 Fq, read 2026-09-09):
    penumbra crates/core/component/governance/src/delegator_vote/proof.rs
      `DelegatorVoteProofPublic` (:35-46), `DelegatorVoteProofPrivate` (:50-63),
      `impl ConstraintSynthesizer<Fq> for DelegatorVoteCircuit` (:150-242)
    value arm:  `note_var.value().commit(v_blinding_vars)?` `.enforce_equal(&claimed_balance_commitment_var)`
                  (proof.rs:215-217) — byte-identical to Spend's value arm.
    commitment: crates/core/asset/src/balance/commitment.rs `Value::commit` (:18-26) /
                  `ValueVar::commit` (:30-43):  C = v · G_a + blinding · H,  H = VALUE_BLINDING_GENERATOR
    range:      crates/core/num/src/amount.rs `AmountVar::new_variable` (:193-207) → `bit_constrain _ 128`
    verifier:   crates/core/component/governance/src/action_handler/delegator_vote.rs
                  `check_stateless` (:42-51) RECOMPUTES `balance_commitment = body.value.commit(Fr::zero())`
                  from the TRANSPARENT `DelegatorVoteBody.value` (delegator_vote/action.rs:34-35).
    honest prover: delegator_vote/plan.rs:109 (`commit(Fr::zero())`), :117 (`v_blinding: Fr::from(0)`).

  WHAT THIS CIRCUIT'S VALUE ARM GUARDS (the divergence from Spend — read this first):
    A DelegatorVote does NOT spend the note and its proof's `balance_commitment` NEVER enters the
    binding signature. The action's ledger contribution is a different object entirely:
      `+unbonded_amount @ VotingReceiptToken(proposal)`, zero blinding
      (crates/core/transaction/src/is_action.rs:49-56),
    tied to `body.value` only by the STATEFUL exchange-rate check
    `check_unbonded_amount_correct_exchange_for_proposal` (governance component/view.rs:284-305).
    So the value arm here guards VOTING-POWER integrity — "the voter's witnessed delegation note
    carries exactly the (asset, amount) the body declares as its vote" — not token supply. A
    prover who could open the recomputed commitment to a different (asset, amount) would vote with
    voting power they do not hold; the receipt-token mint would then inflate through the stateful
    rate check. That mint is a state-machine obligation, OUT OF SCOPE here.

  SCOPE. Only the value-bearing fields are modelled. The remaining public inputs / witnesses of
  `DelegatorVoteCircuit` are owned by sibling obligations and deliberately omitted:
    anchor, state_commitment_proof (Merkle path)     → Penumbra/Circuits/Tct
      NOTE: the inclusion check is UNCONDITIONAL (`&Boolean::TRUE`, proof.rs:197-203) — there is
      no dummy-vote short-circuit, unlike Spend's `is_not_dummy`. A zero-value note still needs
      inclusion.
    start_position: commitment index = 0 (proof.rs:219-223) and the STRICT
      `position < start_position` (`enforce_cmp … Less, false`, proof.rs:234-238)
                                                     → Penumbra/Circuits/Tct + governance state
    nullifier, nk, position                          → Penumbra/Circuits/NullifierDerivation
    rk, ak, spend_auth_randomizer, ivk/address       → spend-authority (not a value arm)
    unbonded_amount, VotingReceiptToken, proposal    → stateful governance (see above)

  STATUS: DRAFT for cryptographer review. Every `-- REVIEW:` marks a fidelity question.
-/
import Penumbra.Circuits.ValueCommit.Basic

namespace Penumbra.Circuits.DelegatorVote

open Penumbra.Circuits.ValueCommit (Element AssetId valueGenerator)

/-! ## The commitment shape

Verbatim from `Penumbra.Circuits.Spend.Basic` (NOT imported — sibling files are edited in
parallel and a shared import would couple their build states). `ValueCommit.Basic` exposes
`Element`, `AssetId`, `valueGenerator` as bare axiom types with no group structure, so — as
ironwood's `ValueShape` does — the group operations, the blinding generator `H` and the
blinding-scalar type are carried as a record parameter rather than minting new axioms.
REVIEW: hoist this record into `Penumbra/Circuits/ValueCommit` once Spend/Output/Swap/
DelegatorVote all agree on it; when `Penumbra.Arithmetic` lands, instantiate it once for
decaf377 and delete the parameter. -/

/-- Pedersen shape of `Value::commit`: `commit a v r = v · G_a + r · H`. -/
structure CommitShape where
  /-- Blinding scalar type. Mirrors `v_blinding : Fr` (decaf377 scalar field). -/
  Blinding : Type
  /-- decaf377 group law (abstract). -/
  add : Element → Element → Element
  /-- Scalar multiplication by an amount. Mirrors `G_v.scalar_mul_le(amount.to_bits_le())`. -/
  smulAmount : Nat → Element → Element
  /-- Scalar multiplication by a blinding scalar. Mirrors
      `value_blinding_generator.scalar_mul_le(value_blinding.to_bits_le())`.
      REVIEW: in-circuit the scalar is 32 witnessed `UInt8`s of `Fr::to_bytes()` fed as 256 bits
      (proof.rs:167-168); out-of-circuit it is the reduced `Fr`. Whether these agree for all byte
      strings a malicious prover may witness (non-canonical encodings ≥ r) is a fidelity question
      for this field. -/
  smulBlinding : Blinding → Element → Element
  /-- `VALUE_BLINDING_GENERATOR` = `encode_to_curve(blake2b("decaf377-rdsa-binding"))`. -/
  H : Element

/-- `Value::commit` (crates/core/asset/src/balance/commitment.rs:18-26). -/
noncomputable def CommitShape.commit (S : CommitShape) (a : AssetId) (v : Nat) (r : S.Blinding) : Element :=
  S.add (S.smulAmount v (valueGenerator a)) (S.smulBlinding r S.H)

/-! ## Public instance and private witness (value-bearing projection) -/

/-- Value-bearing projection of `DelegatorVoteProofPublic` (delegator_vote/proof.rs:35-46).
    Wire layout fed to Groth16 by `DelegatorVoteProof::verify` (proof.rs:374-380):
    `anchor ++ balance_commitment ++ nullifier ++ rk ++ start_position` field elements. -/
structure PublicInputs where
  /-- `DelegatorVoteProofPublic.balance_commitment : balance::Commitment` (proof.rs:38-39),
      allocated in-circuit as `BalanceCommitmentVar::new_input` (proof.rs:180-181). One decaf377
      element, `to_field_elements` → its Fq encoding (proof.rs:376).
      NOT chosen by the prover: the verifier recomputes it from the transparent body (see
      `publicOf`). -/
  balanceCommitment : Element

/-- Value-bearing projection of `DelegatorVoteProofPrivate` (delegator_vote/proof.rs:50-63). -/
structure Witness (S : CommitShape) where
  /-- `note.value().amount : Amount` (u128) — `private.note` (proof.rs:54), reached through
      `NoteVar::new_witness` (proof.rs:154) → `ValueVar` → `AmountVar::new_variable`, which
      enforces `bit_constrain _ 128` (crates/core/num/src/amount.rs:193-207). Modelled as an
      unbounded `Nat`; the bound is a CONCLUSION of `ValueSpec`, not an assumption on the type.
      Semantically this is the note's DELEGATION-TOKEN amount, i.e. the voting power in
      delegation-token units (converted to unbonded units statefully, out of scope). -/
  amount : Nat
  /-- `note.value().asset_id : asset::Id`; `AssetIdVar::value_generator` recomputes `G_a`
      in-circuit. Semantically a delegation token `delegation_<validator>`; the circuit does NOT
      constrain it to be one (that is `validator_by_delegation_asset`, stateful).
      REVIEW: the in-circuit generator derivation (poseidon377 + encode_to_curve) is assumed to
      agree with the out-of-circuit `valueGenerator`; that agreement is its own obligation. -/
  assetId : AssetId
  /-- `v_blinding : Fr` (proof.rs:56), witnessed as `UInt8::new_witness_vec` of its bytes
      (proof.rs:167-168). The honest prover uses `Fr::from(0)` (plan.rs:117) but the circuit does
      NOT constrain it to zero — a malicious prover may witness any scalar. -/
  blinding : S.Blinding

/-! ## The transparent action body (what the chain sees) -/

/-- The value-relevant part of `DelegatorVoteBody` (delegator_vote/action.rs:34-35):
    `value : Value` — the staked note's value, IN THE CLEAR. (`unbonded_amount`, :36-37, is the
    stateful conversion and is not a circuit input.) -/
structure VoteBody where
  amount : Nat
  assetId : AssetId

/-- The verifier's recomputation of the public input, `check_stateless` step 2
    (action_handler/delegator_vote.rs:42-51): `balance_commitment: value.commit(Fr::zero())`.
    `zero` is `Fr::zero()` — passed as an explicit parameter rather than baked into
    `CommitShape` so the shared record stays identical to Spend's.
    REVIEW: native `Value::commit` (commitment.rs:18-26), the same formula as the circuit's
    `ValueVar::commit` (:30-43); their agreement as group elements — in particular that a zero
    blinding scalar contributes the identity on both sides — is silently needed here. Flagged,
    not assumed. -/
noncomputable def publicOf (S : CommitShape) (zero : S.Blinding) (b : VoteBody) : PublicInputs where
  balanceCommitment := S.commit b.assetId b.amount zero

/-! ## The deployed relation vs. what we read off it -/

/-- The R1CS relation of the DEPLOYED `DelegatorVoteCircuit::generate_constraints`, abstract. This
    is the `DeployedR1CS.Satisfies` that `Penumbra.Snark.groth16_verify_implies_witness` hands us
    a witness for; the circuit-vs-model gap lives exactly here (see Snark/Contract/DeployedR1CS.lean).
    REVIEW: to be replaced by the extracted constraint system once the arkworks R1CS is reified. -/
axiom Satisfies (S : CommitShape) : PublicInputs → Witness S → Prop

/-- The value arm of `generate_constraints`, read off the Rust (DRAFT):
    1. amount range — `AmountVar` allocation side effect `bit_constrain _ 128`
       (REVIEW: the `Result` of `bit_constrain` is discarded (`let _ =`, amount.rs:204);
       enforcement is a CS side effect);
    2. commitment integrity — `note_var.value().commit(v_blinding_vars)` `enforce_equal` the
       public `balance_commitment` (proof.rs:215-217).
    The value arm is unconditional; nothing in this circuit gates it. -/
def ValueSpec (S : CommitShape) (pub : PublicInputs) (wit : Witness S) : Prop :=
  wit.amount < 2 ^ 128 ∧
  pub.balanceCommitment = S.commit wit.assetId wit.amount wit.blinding

/-! ## The obligations -/

/-- **DelegatorVote value-commitment soundness (DRAFT — for cryptographer review, not yet proven).**

    Any witness satisfying the deployed DelegatorVote R1CS has an in-range amount and opens the
    public `balance_commitment` to exactly that amount, on that asset, under the Pedersen shape.
    Informally: an R1CS-satisfying DelegatorVote proof commits to exactly the voting power of the
    note it witnesses — mirror of `Spend.spend_valueAccounted`; the value arm is the same Rust.

    What this does NOT say (see header): nothing about the transaction balance. The DelegatorVote
    proof's commitment is never summed by the binding signature; the ledger-side statement is
    `delegatorVote_votingPowerDeclared` below, and the receipt-token mint is stateful and omitted.

    Composition (not stated here): `groth16_verify_implies_witness` supplies `wit` from a verifying
    proof; binding of the commitment (`ValueCommit.generator_independence`) makes the opened
    (asset, amount) unique.

    Solid: the value arm's constraint sites and the 128-bit range site (byte-identical to Spend).
    Draft: `Satisfies` is abstract; `CommitShape` is a placeholder for decaf377; the blinding-scalar
    encoding and in-circuit generator derivation are `REVIEW` items on the fields above. -/
theorem delegatorVote_valueAccounted (S : CommitShape) (pub : PublicInputs) (wit : Witness S)
    (h : Satisfies S pub wit) :
    ValueSpec S pub wit := by
  sorry  -- PROOF OBLIGATION: value-arm soundness of the deployed DelegatorVote R1CS.

open Classical in
/-- Per-asset value of a single `(asset, amount)` pair: `a ↦ amount` if `a` is the asset, else 0.
    Stated this way (rather than `wit.assetId = body.assetId`) because with `amount = 0` the
    generator `G_a` has zero coefficient and the asset is NOT pinned by the commitment — the
    per-asset form is exactly what Pedersen binding yields. Classical decidability on the opaque
    `AssetId`; noncomputable by design. Same idea as `Swap.netOf`. -/
noncomputable def valueAt (assetId : AssetId) (amount : Nat) (a : AssetId) : Nat :=
  if assetId = a then amount else 0

/-- **DelegatorVote voting-power integrity (DRAFT — `sorry`).**

    Informally: an R1CS-satisfying DelegatorVote witness, verified against the public input the
    chain RECOMPUTES from the transparent body (`publicOf`), witnesses a delegation note whose
    per-asset value is exactly the value the body declares as its vote. This is the
    counterfeiting-relevant statement for this circuit: no voting power is created by the proof.

    Why this is not definitional: `ValueSpec` gives
        S.commit wit.assetId wit.amount wit.blinding  =  S.commit body.assetId body.amount zero
    i.e. two Pedersen commitments over *independently sourced* (asset, amount, blinding) agree as
    group elements. Concluding the (asset, amount) pairs agree needs
      * binding of the multi-asset Pedersen commitment
        (`ValueCommit.generator_independence`: no DL relation among `G_a`, `H`), and
      * the 128-bit range clause (so amounts are canonical, not `v` vs `v + |G|`).
    The blinding scalars need NOT agree and are not claimed to (the prover's `v_blinding` is free).
    REVIEW: with `generator_independence` still `True`, this theorem CANNOT be proven from the
    file's axioms; the statement is what matters at this stage. -/
theorem delegatorVote_votingPowerDeclared (S : CommitShape) (zero : S.Blinding)
    (body : VoteBody) (wit : Witness S)
    (hsat : Satisfies S (publicOf S zero body) wit) :
    ∀ a : AssetId, valueAt wit.assetId wit.amount a = valueAt body.assetId body.amount a := by
  sorry  -- PROOF OBLIGATION: delegatorVote_valueAccounted + Pedersen binding + range clause.

/-! ## Residual REVIEW items (not expressible above yet)

  * `Proof::deserialize_compressed_unchecked` in `DelegatorVoteProof::verify` (proof.rs:360) —
    point validity / proof malleability. Belongs to the Groth16 trust boundary
    (`Snark/TrustBoundary/Groth16.lean`: "knowledge-soundness only").
  * `rk` is decompressed with `vartime_decompress` (proof.rs:362-364) before being fed as a public
    input; spend-authority scope.
  * The circuit accepts `amount = 0` votes (no dummy gate); harmless for THIS obligation (voting
    power 0) but the note must still be included under the anchor.
  * The transparent `body.value` is also what the stateful rate check converts to
    `unbonded_amount`; the `valueAt` conclusion is the hand-off point to that (out-of-scope)
    state-machine obligation.
-/

end Penumbra.Circuits.DelegatorVote
