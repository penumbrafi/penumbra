/-
  ╔════════════════════════════════════════════════════════════════════════════════════════╗
  ║  DRAFT FOR CRYPTOGRAPHER REVIEW — SKELETON, NOT A PROOF.                               ║
  ║  Every theorem below is `sorry`. Every structure field and every clause of `SwapSpec`  ║
  ║  is a *transcription* of the arkworks R1CS code by a non-cryptographer and MUST be     ║
  ║  checked against the Rust before anything downstream is trusted. `-- REVIEW:` marks    ║
  ║  the places where the transcription is least certain.                                  ║
  ╚════════════════════════════════════════════════════════════════════════════════════════╝

  Penumbra Swap action — value-accounting soundness obligation (frame).

  STYLE: mirrors zcash/ironwood (Apache-2.0 / MIT), `Zcash/Circuits/Action/Spec.lean`:
  a circuit-independent `Spec : PublicInputs → PrivateWitness → Prop`, one clause per
  in-circuit `enforce_equal` (plus the range clause), each citing the Rust line it mirrors;
  the circuit ↔ spec boundary (`actionSpec_iff_specPost` there) is kept as an EXPLICIT
  hypothesis here, never hidden. Swap is Penumbra-specific (DEX), so there is no ironwood
  circuit to mirror — only the style.

  SOURCE OF TRUTH (penumbra repo, read 2026-09-08):
    crates/core/component/dex/src/swap/proof.rs        SwapProofPublic / SwapProofPrivate /
                                                        SwapCircuit::generate_constraints
    crates/core/component/dex/src/swap/plaintext.rs    SwapPlaintextVar (alloc, delta_i_value, commit)
    crates/core/component/dex/src/swap/action.rs       SwapBody, Swap::balance_commitment_inner
    crates/core/component/dex/src/component/action_handler/swap.rs   check_stateless (verify call)
    crates/core/component/dex/src/trading_pair.rs      TradingPairVar::new_variable_unchecked
    crates/core/asset/src/balance.rs                   BalanceVar::{from_negative_value_var, commit}
    crates/core/num/src/amount.rs                      AmountVar::new_variable (bit_constrain 128)

  WHERE MULTI-ASSET VALUE FLOWS IN (the subtle part):
    A Swap DEBITS two assets at once — delta_1 of asset_1 and delta_2 of asset_2 of the
    trading pair — plus a claim fee. Unlike Spend/Output the two deltas are TRANSPARENT:
    they sit in the clear in `SwapBody`, and the verifier RECOMPUTES the public
    `balance_commitment` from them with ZERO blinding (`balance_commitment_inner`) before
    calling `SwapProof::verify`. The circuit then re-derives the same commitment from its
    witnessed `SwapPlaintext` and enforces equality. So the soundness question is:
      "does the witness the prover *committed to* (in the swap commitment, later consumed
       by SwapClaim) debit exactly the value the body *declares* to the transaction balance?"
    If those two could diverge, a prover could claim (via SwapClaim) more than was debited.
    Only the fee is hidden (blinded); its commitment is a public input, itself re-checked.
    The value RELEASE side (outputs of the swap) is SwapClaim's obligation, not this file's.
-/
import Penumbra.Circuits.ValueCommit.Basic
import Penumbra.Snark.Contract.DeployedR1CS

namespace Penumbra.Circuits.Swap

open Penumbra.Circuits.ValueCommit (Element AssetId valueGenerator)

/-! ## Abstract carriers (reuse `ValueCommit`'s; add only what Swap needs)

`ValueCommit.Element` carries no group instances yet, so the group operations used by the
spec are axiomatized here by name. REVIEW: these should collapse into `Penumbra.Arithmetic`
once decaf377 is modelled; until then they are uninterpreted. -/

/-- Group addition on decaf377 elements. -/
axiom Element.add : Element → Element → Element
/-- Group negation on decaf377 elements. -/
axiom Element.neg : Element → Element
/-- Scalar multiplication by a natural (the in-circuit `scalar_mul_le` over `to_bits_le`). -/
axiom Element.smul : Nat → Element → Element
/-- Blinding scalar (decaf377 `Fr`). -/
axiom Blinding : Type
/-- The literal zero blinding: `UInt8::constant_vec(&[0u8; 32])` in proof.rs
    (transparent commitment). -/
axiom Blinding.zero : Blinding
/-- `VALUE_BLINDING_GENERATOR` (balance.rs `BalanceVar::commit`). -/
axiom blindingGenerator : Element
/-- `blinding · H`. -/
axiom Element.blind : Blinding → Element
/-- Swap commitment — a `tct::StateCommitment` (an `Fq`), the Poseidon377 `hash_7 ∘ hash_4`
    of the whole plaintext (plaintext.rs:207-240). Opaque here. -/
axiom StateCommitment : Type
/-- Opaque payload fields of the plaintext that enter the swap commitment but carry no value:
    `claim_address` (its diversified generator, compressed) and `rseed`. -/
axiom Address : Type
axiom Rseed : Type

/-! ## The circuit's public inputs and private witness -/

/-- Mirrors `SwapProofPublic` (proof.rs:35-44). Order matters: `verify` feeds these to
    Groth16 as `balance_commitment ++ swap_commitment ++ fee_commitment` field elements. -/
structure PublicInputs where
  /-- `balance_commitment : balance::Commitment` — the action's contribution to the tx
      balance. RECOMPUTED BY THE VERIFIER from the transparent body (see `publicOf`). -/
  balanceCommitment : Element
  /-- `swap_commitment : tct::StateCommitment` — `body.payload.commitment`. -/
  swapCommitment : StateCommitment
  /-- `fee_commitment : balance::Commitment` — `body.fee_commitment`, blinded. -/
  feeCommitment : Element

/-- Mirrors `SwapProofPrivate` (proof.rs:46-53) with `SwapPlaintext` flattened to the
    fields `SwapPlaintextVar` allocates (plaintext.rs:183-190, 247-290).
    REVIEW: field set + allocation modes; nothing else of the plaintext is witnessed. -/
structure PrivateWitness where
  /-- `fee_blinding : Fr`, allocated as `UInt8::new_witness_vec` of its bytes (proof.rs). -/
  feeBlinding : Blinding
  /-- `trading_pair.asset_1` — via `TradingPairVar::new_variable_unchecked`.
      REVIEW: NO canonical-ordering check in-circuit (trading_pair.rs:156); the Rust comment
      (plaintext.rs:259-262) argues direction is pinned only by swap-commitment binding.
      The spec below therefore does NOT assume `asset1 < asset2`. -/
  asset1 : AssetId
  /-- `trading_pair.asset_2` — same caveat. -/
  asset2 : AssetId
  /-- `delta_1_i : AmountVar` — amount of `asset1` debited. Allocated through
      `AmountVar::new_variable`, which calls `bit_constrain(_, 128)` (amount.rs:204).
      REVIEW: the `Result` of `bit_constrain` is discarded (`let _ =`); enforcement is a
      CS side effect, same caveat as `ValueCommit.amount_range_enforced`. -/
  delta1 : Nat
  /-- `delta_2_i : AmountVar` — amount of `asset2` debited. Same allocation path. -/
  delta2 : Nat
  /-- `claim_fee : ValueVar` = (amount, asset_id). `ValueVar::new_variable` (value.rs:300)
      allocates the amount through `AmountVar::new_variable`, so it is bit-constrained to
      128 bits like the deltas. REVIEW: the fee asset is NOT constrained to relate to the
      trading pair in any way. -/
  claimFeeAmount : Nat
  claimFeeAsset : AssetId
  /-- `claim_address : AddressVar` — enters the swap commitment only. -/
  claimAddress : Address
  /-- `rseed : FqVar` (bytes reduced mod order) — enters the swap commitment only. -/
  rseed : Rseed

/-! ## The transparent action body (what the chain sees) -/

/-- The value-relevant part of `SwapBody` (action.rs:84-90). `delta_1_i`, `delta_2_i` and
    the trading pair are IN THE CLEAR; only `fee_commitment` is a commitment. -/
structure SwapBody where
  asset1 : AssetId
  asset2 : AssetId
  delta1 : Nat
  delta2 : Nat
  feeCommitment : Element

/-! ## Commitment semantics (transcribed from `BalanceVar::commit`, balance.rs:403-437) -/

/-- One balance contribution: (asset, sign, amount). Sign convention from the circuit:
    `conditionally_select(sign, vG, -vG)` — `true` selects `+vG` (credit), `false` selects
    `-vG` (debit). Every Swap contribution is built by `from_negative_value_var`
    (balance.rs:443-449) and is therefore `false`. -/
abbrev Contribution := AssetId × Bool × Nat

/-- `±amount · G_asset` for one contribution. -/
noncomputable def contribTerm : Contribution → Element
  | (a, true,  v) => Element.smul v (valueGenerator a)
  | (a, false, v) => Element.neg (Element.smul v (valueGenerator a))

/-- `BalanceVar::commit`: `blinding·H + Σ ±v_i·G_{a_i}`, accumulated left to right.
    REVIEW: this is the CIRCUIT-side formula; the native `Balance::commit` (balance.rs:154)
    first *aggregates* same-asset entries. The two must agree as group elements for the
    spec to be faithful — that agreement (`Balance::commit = BalanceVar::commit` on the
    vectorised form) is itself an unproven obligation. -/
noncomputable def balanceCommit (cs : List Contribution) (r : Blinding) : Element :=
  cs.foldl (fun acc c => Element.add acc (contribTerm c)) (Element.blind r)

/-- The swap commitment `SwapPlaintextVar::commit` (plaintext.rs:207-240):
    `hash_7(ds, rseed, fee.amount, fee.asset, g_d, pk_d, ck, hash_4(ds, a1, a2, d1, d2))`.
    Opaque; only its INPUTS are pinned here so a collision-resistance assumption can
    later be stated over exactly this argument list.
    REVIEW: argument order/arity vs the Rust; `g_d`/`pk_d`/clue key are folded into
    `Address` here. -/
axiom swapCommit :
  AssetId → AssetId → Nat → Nat → Nat → AssetId → Address → Rseed → StateCommitment

/-- The verifier's recomputation of the public input, `Swap::balance_commitment_inner`
    (action.rs:24-38), as called from `check_stateless` (action_handler/swap.rs:26-33):
    `(-Balance(d1@a1)).commit(0) + (-Balance(d2@a2)).commit(0) + body.fee_commitment`.
    REVIEW: native `Balance::commit`, NOT `BalanceVar::commit` — see `balanceCommit` note.
    Here it is transcribed with the same abstract formula; the two-commit-then-add form
    yields `0·H + (-d1·G1)` `+` `0·H + (-d2·G2)`, which is where `blind zero = identity` is
    silently needed. Flagged, not assumed. -/
noncomputable def publicOf (b : SwapBody) (swapC : StateCommitment) : PublicInputs where
  balanceCommitment :=
    Element.add
      (Element.add (balanceCommit [(b.asset1, false, b.delta1)] Blinding.zero)
                   (balanceCommit [(b.asset2, false, b.delta2)] Blinding.zero))
      b.feeCommitment
  swapCommitment := swapC
  feeCommitment  := b.feeCommitment

/-! ## The deployed Swap statement (ironwood `ActionSpec` analogue) -/

/-- The Swap R1CS relation, one clause per constraint site in
    `SwapCircuit::generate_constraints` (proof.rs:103-141) plus the allocation-time range
    clause. DRAFT — every clause is a transcription to be reviewed. -/
def SwapSpec (pub : PublicInputs) (wit : PrivateWitness) : Prop :=
  -- range: every `AmountVar` is bit-constrained to 128 bits at allocation (amount.rs:204)
  wit.delta1 < 2 ^ 128 ∧ wit.delta2 < 2 ^ 128 ∧ wit.claimFeeAmount < 2 ^ 128 ∧
  -- swap-commitment integrity: `claimed_swap_commitment.enforce_equal(&swap_commitment)`
  pub.swapCommitment =
    swapCommit wit.asset1 wit.asset2 wit.delta1 wit.delta2
      wit.claimFeeAmount wit.claimFeeAsset wit.claimAddress wit.rseed ∧
  -- fee-commitment integrity: `claimed_fee_commitment.enforce_equal(&fee_commitment)`
  --   fee_balance = from_negative_value_var(claim_fee); committed with `fee_blinding`
  pub.feeCommitment =
    balanceCommit [(wit.claimFeeAsset, false, wit.claimFeeAmount)] wit.feeBlinding ∧
  -- balance-commitment integrity: `claimed_balance_commitment.enforce_equal(&total)`
  --   total = (−d1@a1).commit(0) + (−d2@a2).commit(0) + fee_commitment
  --   (the in-circuit `fee_commitment` is already forced equal to `pub.feeCommitment`
  --    by the previous clause, so it is written with the public value here)
  pub.balanceCommitment =
    Element.add
      (Element.add (balanceCommit [(wit.asset1, false, wit.delta1)] Blinding.zero)
                   (balanceCommit [(wit.asset2, false, wit.delta2)] Blinding.zero))
      pub.feeCommitment

/-- The value a satisfying witness *actually* debits from the transaction: both trading-pair
    inputs and the fee, all negative.
    REVIEW: to be wired into `Penumbra.Security.Ledger.NetValue` (currently an opaque axiom
    type) once that carries a real asset ↦ signed-amount map. -/
def contribution (wit : PrivateWitness) : List Contribution :=
  [ (wit.asset1, false, wit.delta1),
    (wit.asset2, false, wit.delta2),
    (wit.claimFeeAsset, false, wit.claimFeeAmount) ]

/-- The value the transparent body *declares* it debits (fee left as its commitment). -/
def declared (b : SwapBody) : List Contribution :=
  [ (b.asset1, false, b.delta1),
    (b.asset2, false, b.delta2) ]

/-- The two trading-pair debits of a witness (the fee is excluded: it is blinded and is
    compared only as a commitment, never as clear value). -/
def pairDebits (wit : PrivateWitness) : List Contribution :=
  [ (wit.asset1, false, wit.delta1),
    (wit.asset2, false, wit.delta2) ]

open Classical in
/-- Per-asset signed net of a contribution list: `asset ↦ Σ ±amount`. This — not slot-wise
    list equality — is the right conclusion, because a Pedersen sum is SYMMETRIC (the pair
    `(a1,d1),(a2,d2)` and `(a2,d2),(a1,d1)` commit identically) and AGGREGATING (with
    `a1 = a2`, which the circuit does not exclude, `(a,d1+1),(a,d2-1)` commit identically).
    Classical decidability on the opaque `AssetId`; noncomputable by design.
    REVIEW: this is what `Penumbra.Security.Ledger.NetValue` must become. -/
noncomputable def netOf (cs : List Contribution) (a : AssetId) : Int :=
  cs.foldl
    (fun acc c => match c with
      | (x, s, v) => if x = a then acc + (if s then (v : Int) else -(v : Int)) else acc)
    0

/-! ## The obligation -/

/-- **Swap value accounting (DRAFT — `sorry`).**

    Informally: an R1CS-satisfying Swap witness, verified against the public inputs the
    chain recomputes from the transparent body, debits EXACTLY the two-asset value the body
    declares — no value is created across the swap. Concretely, the PER-ASSET NET of the
    witnessed `(asset1, delta1, asset2, delta2)` that the prover has bound into the swap
    commitment (and will later redeem via SwapClaim) equals the per-asset net of the body's.
    The *ordered pair* is deliberately NOT claimed — it is pinned only by swap-commitment
    binding + SwapClaim's consumption of that commitment, which is out of scope here.

    Why this is not definitional: `SwapSpec` gives
        pub.balanceCommitment = C_circuit(wit)      and      pub = publicOf body
    i.e. two Pedersen sums over *independently sourced* (asset, amount) pairs agree as group
    elements. Concluding the pairs themselves agree needs
      * binding of the multi-asset Pedersen commitment
        (`ValueCommit.generator_independence`: no DL relation among `G_a`, `H`), and
      * the 128-bit range clause (so amounts are canonical, not `v` vs `v + |G|`), and
      * cancellation of the common `pub.feeCommitment` term.
    REVIEW: with `generator_independence` still `True`, this theorem CANNOT be proven from
    the file's axioms; the statement is what matters at this stage. Equality of two
    fee-side terms does not (and should not) follow — the fee is blinded. -/
theorem swap_valueAccounted
    (body : SwapBody) (swapC : StateCommitment) (wit : PrivateWitness)
    (hsat : SwapSpec (publicOf body swapC) wit) :
    ∀ a : AssetId, netOf (pairDebits wit) a = netOf (declared body) a := by
  sorry  -- PROOF OBLIGATION: Pedersen binding over independent generators + range clause.

/-- **Through the SNARK (DRAFT — `sorry`).** The same statement lifted to a verifying
    Groth16 proof, via `Snark.groth16_verify_implies_witness`, under an EXPLICIT bridge
    hypothesis `hbridge` that the deployed R1CS's satisfaction relation implies `SwapSpec`
    on the decoded public input / witness. That bridge is ironwood's
    `actionSpec_iff_specPost` seam and is the SPEC-vs-DEPLOYED-CIRCUIT gap
    (`Snark.DeployedR1CS` header) — kept as a hypothesis, never discharged silently.
    REVIEW: `decodePub`/`decodeWit` are the arkworks `to_field_elements` layout
    (proof.rs `verify`: balance ++ swap ++ fee); a wrong layout makes `hbridge` vacuous. -/
theorem swap_valueAccounted_snark
    (cs : Penumbra.Snark.DeployedR1CS)
    (decodePub : cs.PublicInput → PublicInputs) (decodeWit : cs.Witness → PrivateWitness)
    (hbridge : ∀ x w, cs.Satisfies x w → SwapSpec (decodePub x) (decodeWit w))
    (body : SwapBody) (swapC : StateCommitment)
    (vk : cs.VerifyingKey) (x : cs.PublicInput) (π : cs.Proof)
    (hx : decodePub x = publicOf body swapC)
    (hverify : cs.Verify vk x π = true) :
    ∃ w : cs.Witness,
      ∀ a : AssetId, netOf (pairDebits (decodeWit w)) a = netOf (declared body) a := by
  sorry  -- PROOF OBLIGATION: groth16_verify_implies_witness ∘ hbridge ∘ swap_valueAccounted.

/-! ## Residual REVIEW items (not expressible above yet)

  * `Proof::deserialize_compressed_unchecked` in `SwapProof::verify` — point validity /
    proof malleability. Out of knowledge-soundness scope; belongs to the Groth16 trust
    boundary file (`Snark/TrustBoundary/Groth16.lean`: "knowledge-soundness only").
  * Same-asset trading pair (`asset1 = asset2`) is not excluded in-circuit. The per-asset
    `netOf` conclusion handles this by aggregation (it is exactly why the theorem is NOT
    stated as ordered-pair equality). Whether native `Balance::commit` (which aggregates)
    and `BalanceVar::commit` (which does not) still agree as group elements is part of the
    `balanceCommit` note.
  * `delta1 = delta2 = 0` swaps are accepted by the circuit; harmless for THIS obligation
    (debit 0), but relevant to SwapClaim / batch-output accounting.
  * The fee asset is arbitrary; the fee is debited to the tx balance (via the fee
    commitment) and re-appears as a credit in SwapClaim — that round trip is SwapClaim's.
-/

end Penumbra.Circuits.Swap
