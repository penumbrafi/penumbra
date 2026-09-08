/-
  Spend circuit — value-accounting soundness frame (SKELETON, no proof).

  Structure mirrored from zcash/ironwood (Apache-2.0 / MIT):
    Zcash/Security/Ledger/Statement.lean  — `ActionInstance` / `ActionWitness` / `ActionSatisfied`
                                            (public instance vs. private witness, statement as Prop)
    Zcash/Security/Ledger/Value.lean      — `ValueShape` (Pedersen shape with abstract bases and a
                                            `commit_eq` law, bases left abstract), `txNetValue`
    Zcash/Circuits/Action/Spec.lean       — the circuit-facing `ActionSpec` conjunct list.
  Ironwood's Action fuses spend+output into one circuit (`cv_net = (v_old − v_new)·V + rcv·R`);
  Penumbra splits them, so this file is the SPEND half: a single positive contribution.

  Real circuit (source of truth, arkworks R1CS over BLS12-377 Fq):
    penumbra crates/core/component/shielded-pool/src/spend/proof.rs
      `SpendProofPublic`, `SpendProofPrivate`, `impl ConstraintSynthesizer<Fq> for SpendCircuit`
    value arm:  `note_var.value().commit(v_blinding_vars)?.enforce_equal(&claimed_balance_commitment_var)`
    commitment: crates/core/asset/src/balance/commitment.rs `Value::commit` / `ValueVar::commit`
                  C = v · G_a + blinding · H,  H = VALUE_BLINDING_GENERATOR
    range:      crates/core/num/src/amount.rs `AmountVar::new_variable` → `bit_constrain _ 128`
    ledger contribution: crates/core/component/shielded-pool/src/spend/plan.rs `SpendPlan::balance`
                  = `Value { amount, asset_id }.into()`  (POSITIVE; no negation anywhere in the path)

  SCOPE. Only the value-bearing fields are modelled here. The remaining public inputs / witnesses
  of `SpendCircuit` are owned by sibling obligations and deliberately omitted:
    anchor, state_commitment_proof (Merkle path)   → Penumbra/Circuits/Tct
    nullifier, nk, position                        → Penumbra/Circuits/NullifierDerivation
    rk, ak, spend_auth_randomizer, ivk/address     → spend-authority (not a supply-integrity arm)

  STATUS: DRAFT for cryptographer review. Every `-- REVIEW:` marks a fidelity question.
-/
import Penumbra.Circuits.ValueCommit.Basic
import Penumbra.Security.Ledger.Balance

namespace Penumbra.Circuits.Spend

open Penumbra.Circuits.ValueCommit (Element AssetId valueGenerator)

/-! ## The commitment shape

`ValueCommit.Basic` exposes `Element`, `AssetId`, `valueGenerator` as bare axiom types with no
group structure, so — as ironwood's `ValueShape` does — we carry the group operations, the blinding
generator `H` and the blinding-scalar type as a record parameter rather than minting new axioms.
When `Penumbra.Arithmetic` lands, instantiate this once for decaf377 and delete the parameter. -/

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
      REVIEW: in-circuit the scalar is 32 witnessed `UInt8`s of `Fr::to_bytes()` fed as 256 bits;
      out-of-circuit it is the reduced `Fr`. Whether these agree for all byte strings a malicious
      prover may witness (non-canonical encodings ≥ r) is a fidelity question for this field. -/
  smulBlinding : Blinding → Element → Element
  /-- `VALUE_BLINDING_GENERATOR` = `encode_to_curve(blake2b("decaf377-rdsa-binding"))`. -/
  H : Element

/-- `Value::commit` (crates/core/asset/src/balance/commitment.rs:17-26). -/
noncomputable def CommitShape.commit (S : CommitShape) (a : AssetId) (v : Nat) (r : S.Blinding) : Element :=
  S.add (S.smulAmount v (valueGenerator a)) (S.smulBlinding r S.H)

/-! ## Public instance and private witness (value-bearing projection) -/

/-- Value-bearing projection of `SpendProofPublic` (spend/proof.rs:40-51). -/
structure PublicInputs where
  /-- `SpendProofPublic.balance_commitment : balance::Commitment`, allocated in-circuit as
      `BalanceCommitmentVar::new_input` (spend/proof.rs:174-175). Wire form: one decaf377
      element, `to_field_elements` → its Fq encoding (spend/proof.rs:341-346). -/
  balanceCommitment : Element

/-- Value-bearing projection of `SpendProofPrivate` (spend/proof.rs:53-68). -/
structure Witness (S : CommitShape) where
  /-- `note.value().amount : Amount` (u128), reached through `NoteVar::new_witness` →
      `ValueVar` → `AmountVar::new_variable`, which enforces `bit_constrain _ 128`
      (crates/core/num/src/amount.rs:193-207). Modelled as an unbounded `Nat`; the bound is a
      CONCLUSION of `ValueSpec`, not an assumption on the type. -/
  amount : Nat
  /-- `note.value().asset_id : asset::Id`; `AssetIdVar::value_generator` recomputes `G_a` in-circuit.
      REVIEW: the in-circuit generator derivation (poseidon377 + encode_to_curve) is assumed to
      agree with the out-of-circuit `valueGenerator`; that agreement is its own obligation. -/
  assetId : AssetId
  /-- `v_blinding : Fr` (spend/proof.rs:61), witnessed as `UInt8::new_witness_vec` of its bytes. -/
  blinding : S.Blinding

/-! ## The deployed relation vs. what we read off it -/

/-- The R1CS relation of the DEPLOYED `SpendCircuit::generate_constraints`, abstract. This is the
    `DeployedR1CS.Satisfies` that `Penumbra.Snark.groth16_verify_implies_witness` hands us a witness
    for; the circuit-vs-model gap lives exactly here (see Snark/Contract/DeployedR1CS.lean).
    REVIEW: to be replaced by the extracted constraint system once the arkworks R1CS is reified. -/
axiom Satisfies (S : CommitShape) : PublicInputs → Witness S → Prop

/-- The value arm of `generate_constraints`, read off the Rust (DRAFT):
    1. amount range — `AmountVar` allocation side effect `bit_constrain _ 128`;
    2. commitment integrity — `note_var.value().commit(v_blinding)` `enforce_equal` the public
       `balance_commitment` (spend/proof.rs:211-213).
    The Merkle short-circuit for dummy spends (`is_not_dummy`, spend/proof.rs:188-199) gates
    only the inclusion check; the value arm is unconditional. -/
def ValueSpec (S : CommitShape) (pub : PublicInputs) (wit : Witness S) : Prop :=
  wit.amount < 2 ^ 128 ∧
  pub.balanceCommitment = S.commit wit.assetId wit.amount wit.blinding

/-! ## Ledger contribution -/

/-- Signed multi-asset value, `asset_id ↦ signed amount`. Proposed CONCRETIZATION of the opaque
    `Penumbra.Security.Ledger.NetValue`; a transaction's net value is the pointwise sum of its
    actions' contributions (plus fee).
    REVIEW: hoist into Security/Ledger/Balance.lean as the definition of `NetValue` when that file
    is unfrozen. -/
def Contribution : Type := AssetId → Int

/-- The single-asset contribution `a ↦ v`, zero elsewhere — stated as a predicate to avoid needing
    `DecidableEq AssetId` on an axiom type. -/
def IsSingleton (c : Contribution) (a : AssetId) (v : Int) : Prop :=
  c a = v ∧ ∀ b : AssetId, b ≠ a → c b = 0

/-- What a Spend DECLARES to the ledger: `SpendPlan::balance` = `+Value { amount, asset_id }`
    (spend/plan.rs:131-137). The sign is solid: neither `ValueVar::commit` nor `SpendPlan::balance`
    negates; a Spend releases its note's value into the transaction. A dummy spend (`amount = 0`)
    therefore contributes zero. -/
def declaredContribution (S : CommitShape) (wit : Witness S) (c : Contribution) : Prop :=
  IsSingleton c wit.assetId (Int.ofNat wit.amount)

/-! ## The obligation -/

/-- **Spend value-accounting soundness (DRAFT — for cryptographer review, not yet proven).**

    Any witness satisfying the deployed Spend R1CS has an in-range amount and opens the public
    `balance_commitment` to exactly that amount, on that asset, under the Pedersen shape.
    Informally: an R1CS-satisfying Spend proof contributes exactly its declared value to the
    transaction balance — no value is created by a Spend.

    Why this is the whole obligation: the contribution a Spend declares to the ledger is
    `+wit.amount` on `wit.assetId` BY DEFINITION (`declaredContribution`), and the ledger never sees
    a `Contribution` directly — it sees only `balance_commitment`, which the binding signature sums.
    So "declared value = committed value" reduces entirely to the value arm being sound.

    Composition (not stated here): `groth16_verify_implies_witness` supplies `wit` from a verifying
    proof; binding of the commitment (`ValueCommit.generator_independence`) makes the opened amount
    unique; the binding signature (Ledger/Balance.lean) sums contributions across the transaction.

    Solid: the direction and sign of the contribution, the 128-bit range site.
    Draft: `Satisfies` is abstract; `CommitShape` is a placeholder for decaf377; the blinding-scalar
    encoding and in-circuit generator derivation are `REVIEW` items on the fields above. -/
theorem spend_valueAccounted (S : CommitShape) (pub : PublicInputs) (wit : Witness S)
    (h : Satisfies S pub wit) :
    ValueSpec S pub wit := by
  sorry  -- PROOF OBLIGATION: value-arm soundness of the deployed Spend R1CS.

/-- A Spend never declares a negative contribution on any asset (structural; holds by definition
    of `declaredContribution`). This is the "no value created" sign check, proven now. -/
theorem declaredContribution_nonneg (S : CommitShape) (wit : Witness S) (c : Contribution)
    (hc : declaredContribution S wit c) (a : AssetId) : 0 ≤ c a := by
  by_cases hab : a = wit.assetId
  · subst hab
    rw [hc.1]
    exact Int.natCast_nonneg _
  · rw [hc.2 a hab]
    exact Int.le_refl 0

end Penumbra.Circuits.Spend
