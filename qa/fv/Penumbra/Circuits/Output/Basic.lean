/-
  Penumbra OUTPUT circuit — value-accounting soundness FRAME.

  STATUS: SCAFFOLD / DRAFT FOR CRYPTOGRAPHER REVIEW. This file STATES the obligation; it proves
  nothing (`sorry`). It is deps-free: only project modules + core Lean 4 (no Clean, no Mathlib).

  Structure mirrors zcash/ironwood (Apache-2.0 / MIT), `Zcash/Circuits/Action/Spec.lean`:
  a circuit-independent `Spec` over (public input, private witness), spelled out as equations,
  with the value-commitment arm `cv = (±v)•G + rcv•R` stated explicitly. Penumbra's Output is the
  "new note only" half of an Orchard Action: it has no spend arm, and its value contribution is
  NEGATIVE (the transaction must fund the note it creates).

  Source of truth (penumbra rev 35511d0, read 2026-09-08, not from memory):
    crates/core/component/shielded-pool/src/output/proof.rs
        `OutputProofPublic { balance_commitment, note_commitment }`
        `OutputProofPrivate { note, balance_blinding }`
        `impl ConstraintSynthesizer<Fq> for OutputCircuit`  (lines 111-136)
    crates/core/asset/src/balance.rs
        `BalanceVar::from_negative_value_var`  (sign := Boolean::constant(false))
        `BalanceVar::commit`                   (conditionally_select(sign, vG, -vG))
        `Balance::commit`                      (native counterpart)
    crates/core/asset/src/balance/commitment.rs  `VALUE_BLINDING_GENERATOR` (= H)
    crates/core/num/src/amount.rs + fixpoint.rs  `AmountVar::new_variable` → `bit_constrain(_, 128)`
    crates/core/keys/src/address/r1cs.rs         diversified-base ≠ identity (`enforce_not_equal`)
-/
import Penumbra.Circuits.ValueCommit.Basic
import Penumbra.Security.Ledger.Balance

namespace Penumbra.Circuits.Output

open Penumbra.Circuits.ValueCommit (Element AssetId valueGenerator)

/-! ## Arithmetic vocabulary not yet owned by a shared module

  REVIEW (architecture): everything in this section belongs in `Penumbra.Circuits.ValueCommit.Basic`
  or `Penumbra.Arithmetic` (one owner for the decaf377 group + scalar field). It is declared here
  ONLY because the shared files are frozen while circuits are being framed in parallel. Consolidate
  before any proof is attempted; every other circuit frame will want the same five symbols. -/

/-- decaf377 scalar field `Fr` (the blinding lives here: `OutputProofPrivate.balance_blinding: Fr`). -/
axiom Fr : Type
/-- Group addition on decaf377 (`commitment = commitment + to_add` in `BalanceVar::commit`). -/
axiom add : Element → Element → Element
/-- Group negation (`vG.negate()` in `BalanceVar::commit`). -/
axiom neg : Element → Element
/-- Scalar multiplication `scalar_mul_le(bits)`; in-circuit the scalar is presented as bits of an
    `Fq` element, natively as an `Fr`. -/
axiom smul : Fr → Element → Element
/-- `VALUE_BLINDING_GENERATOR` = `encode_to_curve(blake2b("decaf377-rdsa-binding"))`, the H of
    `Penumbra.Circuits.ValueCommit`. -/
axiom blindingGenerator : Element
/-- `Fr::from(value.amount)` (u128 → Fr) in `Balance::commit`.
    REVIEW (fidelity): only meaningful for `n < 2^128`; in-circuit the multiplication uses
    `to_bits_le` of the `Fq` amount variable, and the two agree exactly when the amount is a genuine
    128-bit integer — which is what the range conjunct of `OutputSpec` supplies. -/
axiom scalarOfAmount : Nat → Fr
/-- `note::StateCommitment` (an `Fq`), the second public input. Opaque here: note-commitment
    integrity is a separate (non-value) obligation; see `noteCommit`. -/
axiom StateCommitment : Type

/-! ## The Output action's inputs (arkworks `OutputCircuit`, value-relevant projection) -/

/-- A `Value` (`penumbra_sdk_asset::Value`) as witnessed through `ValueVar { amount, asset_id }`.
    `amount` mirrors `AmountVar` (an `FqVar` that `AmountVar::new_variable` bit-constrains to 128
    bits); `assetId` mirrors `AssetIdVar`. -/
structure Value where
  /-- `ValueVar.amount` — `AmountVar`, allocated via `bit_constrain(_, 128)`. -/
  amount  : Nat
  /-- `ValueVar.asset_id` — `AssetIdVar`; its generator is `asset_id.value_generator()`. -/
  assetId : AssetId

/-- Public inputs — `OutputProofPublic`, allocated with `new_input` in source order
    (`StateCommitmentVar` first, then `BalanceCommitmentVar`; proof.rs:120-123).
    REVIEW (fidelity): Groth16 sees each as field elements via `ToConstraintField`; we take the
    decoded decaf377 element / Fq directly. The encoding-injectivity step is elided. -/
structure PublicInputs where
  /-- `OutputProofPublic.balance_commitment : balance::Commitment` (a decaf377 element). -/
  balanceCommitment : Element
  /-- `OutputProofPublic.note_commitment : note::StateCommitment`. -/
  noteCommitment    : StateCommitment

/-- Private witness — the value-bearing projection of `OutputProofPrivate`.
    `note` is allocated as `NoteVar::new_witness`; only `note_var.value()` reaches the balance
    commitment. The note's address (`g_d`, `pk_d`, clue key), `rseed`/note blinding, etc. are
    elided here as note-commitment-side data (they matter for `noteCommit`, not for value).
    REVIEW: the `g_d ≠ identity` check (`AddressVar::new_variable`, address/r1cs.rs:46-48) is a
    real constraint of this circuit but is not value-relevant; it is omitted from this frame. -/
structure PrivateWitness where
  /-- `OutputProofPrivate.note.value()` — the value of the note being CREATED. -/
  value           : Value
  /-- `OutputProofPrivate.balance_blinding : Fr` — witnessed as 32 `UInt8` (proof.rs:116-117). -/
  balanceBlinding : Fr

/-- Note-commitment integrity, abstracted: `note_var.commit()` (proof.rs:131). Depends on the
    elided note fields, so it is left opaque in this VALUE frame. -/
axiom noteCommit : PrivateWitness → StateCommitment

/-! ## The specification -/

/-- The balance commitment an Output MUST open to: `-(v • G_a) + r • H`.

    Sign justification (read, not guessed): proof.rs:126-127 builds
    `BalanceVar::from_negative_value_var(note_var.value())`, which stores
    `(asset_id, (Boolean::constant(false), amount))`; `BalanceVar::commit` computes
    `vG = G_v.scalar_mul_le(bits(amount))`, `minus_vG = vG.negate()`, and
    `conditionally_select(sign, &vG, &minus_vG)` — `sign = false` selects `minus_vG`.
    Native counterpart (`check_satisfaction`): `(-Balance::from(note.value())).commit(blinding)`,
    where `Balance::commit` does `commitment -= G_v * Fr::from(amount)` for `Sign::Required`.
    The blinding is added ONCE: `H.scalar_mul_le(bits(blinding))` seeds the accumulator. -/
noncomputable def outputBalanceCommitment (v : Value) (r : Fr) : Element :=
  add (neg (smul (scalarOfAmount v.amount) (valueGenerator v.assetId)))
      (smul r blindingGenerator)

/-- The deployed Output statement over its public input and private witness
    (ironwood `ActionSpec` shape, Output half only). -/
def OutputSpec (pub : PublicInputs) (wit : PrivateWitness) : Prop :=
  -- the created note's amount is a 128-bit integer: `AmountVar::new_variable` →
  -- `bit_constrain(inner_amount_var, 128)` (fixpoint.rs:717-737 — Boolean witnesses for the low
  -- 128 bits, `le_bits_to_fp_var(...).enforce_equal(&value)`). This conjunct is LOAD-BEARING for
  -- the next one (see `scalarOfAmount`). Obligation named in
  -- `Penumbra.Circuits.ValueCommit.amount_range_enforced` (currently `True`; not usable here).
  -- REVIEW: amount.rs:204/222 discards `bit_constrain`'s `Result` (`let _ =`); constraints are
  -- added as a side effect before the return, so only a `SynthesisError` is swallowed. Confirm no
  -- error path can leave the amount unconstrained while synthesis still succeeds.
  wit.value.amount < 2 ^ 128 ∧
  -- balance-commitment integrity: `balance_commitment.enforce_equal(&claimed_balance_commitment)`
  -- (proof.rs:128)
  pub.balanceCommitment = outputBalanceCommitment wit.value wit.balanceBlinding ∧
  -- note-commitment integrity: `note_commitment.enforce_equal(&claimed_note_commitment)`
  -- (proof.rs:132) — abstract in this value frame
  pub.noteCommitment = noteCommit wit

/-! ## Circuit satisfaction and the obligation -/

/-- "The R1CS emitted by `OutputCircuit::generate_constraints` is satisfied by (pub, wit)."
    REVIEW (seam): this is the `DeployedR1CS.Satisfies` of the Output QAP
    (`Penumbra.Snark.Contract.DeployedR1CS`), to be instantiated there — kept as a local axiom so
    this frame stays within the two permitted imports. The spec-vs-implementation gap (is this the
    QAP of the *deployed* proving key `output_pk`?) lives at that seam, not here. -/
axiom circuitSatisfied : PublicInputs → PrivateWitness → Prop

/-- **DRAFT — for cryptographer review, not a result.**

    Output value-accounting soundness: any satisfying assignment of the Output R1CS opens the
    public `balance_commitment` to exactly MINUS the created note's value (under the witnessed
    blinding), with the amount range-bounded to 128 bits, and binds the note commitment.
    Informally: an R1CS-satisfying Output proof contributes exactly its declared value — negatively,
    since it creates a note — to the transaction's balance.

    What this does NOT say (deferred to other layers):
    * that a *verifying Groth16 proof* yields such an assignment
      (`Penumbra.Snark.groth16_verify_implies_witness`, AGM);
    * that the commitment is *binding* — that no other (value, blinding) opens the same element
      (`Penumbra.Circuits.ValueCommit.generator_independence` + DL on decaf377);
    * that the sum over a transaction's actions nets to zero
      (`Penumbra.Security.Ledger.txConserves`, via the binding signature).

    Together with those, this is the Output arm of `penumbra_supplyIntegrity_measure_le`. -/
theorem output_valueAccounted (pub : PublicInputs) (wit : PrivateWitness)
    (_h : circuitSatisfied pub wit) : OutputSpec pub wit := by
  sorry  -- PROOF OBLIGATION: from a satisfying R1CS assignment, read off the three conjuncts.

/-- The ledger-facing corollary: what an Output contributes. The contribution is the NEGATION of
    the created note's value — `Balance::from(note.value())` negated (`Neg for Balance` flips the
    `negated` flag; the canonical imbalance is `Sign::Required`). Stated as an opening, since
    `Penumbra.Security.Ledger.NetValue` is still opaque; wire to it when that model lands. -/
theorem output_contribution_is_negative_noteValue (pub : PublicInputs) (wit : PrivateWitness)
    (h : circuitSatisfied pub wit) :
    pub.balanceCommitment = outputBalanceCommitment wit.value wit.balanceBlinding :=
  (output_valueAccounted pub wit h).2.1

end Penumbra.Circuits.Output
