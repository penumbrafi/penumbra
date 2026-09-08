/-
  ╔════════════════════════════════════════════════════════════════════════════════════════╗
  ║  DRAFT FOR CRYPTOGRAPHER REVIEW — SKELETON, NOT A PROOF.                               ║
  ║  Every obligation below is `sorry`. Every structure field and every clause of          ║
  ║  `ValueSpec` is a *transcription* of the arkworks R1CS code by a non-cryptographer and  ║
  ║  MUST be checked against the Rust before anything downstream is trusted. `-- REVIEW:`  ║
  ║  marks the places where the transcription is least certain; the fixed-point pro-rata   ║
  ║  arithmetic (`U128x128`) is the least certain of all and is flagged throughout.        ║
  ╚════════════════════════════════════════════════════════════════════════════════════════╝

  Penumbra SwapClaim action — value-accounting soundness obligation (frame).

  STYLE: mirrors zcash/ironwood (Apache-2.0 / MIT), `Zcash/Circuits/Action/Spec.lean`:
  a circuit-independent `ValueSpec : PublicInputs → PrivateWitness → Prop`, one clause per
  in-circuit `enforce_equal` (plus the allocation-time range clauses), each citing the Rust
  line it mirrors; the deployed R1CS relation is the abstract `Satisfies` (Spend's idiom) and
  the obligation is `Satisfies → ValueSpec ∧ per-asset-net equalities` (Swap's `netOf` idiom).
  SwapClaim is Penumbra-specific (DEX), so there is no ironwood circuit to mirror — only the
  style. Ironwood's `ActionSpec` is the shape; its `Action` is spend+output fused, SwapClaim
  is "spend a swap commitment, output two notes".

  SOURCE OF TRUTH (penumbra repo, branch qa/fv, read 2026-09-09):
    crates/core/component/dex/src/swap_claim/proof.rs
        SwapClaimProofPublic (44-57) / SwapClaimProofPrivate (61-78) /
        SwapClaimCircuit::generate_constraints (190-301) / SwapClaimProof::verify (444-514)
    crates/core/component/dex/src/batch_swap_output_data.rs
        BatchSwapOutputData (22-41), native pro_rata_outputs (47-80),
        BatchSwapOutputDataVar alloc (150-200), R1CS pro_rata_outputs (230-276)
    crates/core/component/dex/src/swap/plaintext.rs      output_notes (65-92), SwapPlaintextVar
    crates/core/component/dex/src/swap_claim/action.rs   SwapClaim::balance (25-27) = +fee
    crates/core/component/dex/src/swap_claim/plan.rs     SwapClaimPlan::balance (126-136)
    crates/core/component/dex/src/component/action_handler/swap_claim.rs
        check_stateless (27-44: public-input assembly), check_historical (46-77: BSOD lookup)
    crates/core/num/src/fixpoint.rs
        U128x128 (U256, 128 integer + 128 fractional bits): round_down 102, checked_mul 119,
        checked_div 156; U128x128Var: checked_add 278, checked_mul 334, checked_div 472,
        round_down 634, round_down_to_amount 651
    crates/core/num/src/fixpoint/div.rs   stub_div_rem_u384_by_u256 (8-25): (x·2^128)/y, Err on
                                          y = 0 or quotient ≥ 2^256
    crates/core/num/src/amount.rs         AmountVar::new_variable → bit_constrain(_,128) (204);
                                          U128x128Var::from_amount_var (513-525)

  WHERE VALUE FLOWS (the shape of the obligation):
    A SwapClaim REDEEMS a swap. The Swap action already DEBITED `delta_1_i` of asset_1,
    `delta_2_i` of asset_2 and a claim fee from the transaction balance (see Swap/Basic.lean),
    binding all of it into a swap commitment now sitting in the SCT. The batch executed at the
    swap's block and published `BatchSwapOutputData` (BSOD) — the clearing prices. The claim
    must output EXACTLY the user's pro-rata share of the batch output, as two fresh notes to
    the swap's `claim_address`, and it CREDITS the pre-paid fee back to the transaction balance
    (`SwapClaim::balance = +fee`, so the transaction's own fee can be paid from it).
    Crucially, the two output notes DO NOT pass through the transaction balance at all: the
    chain inserts `output_1_commitment`/`output_2_commitment` into the SCT directly
    (`check_and_execute`, action_handler/swap_claim.rs:83-88). The ONLY thing standing between
    a prover and minting arbitrary notes here is this circuit's `pro_rata_outputs` +
    note-commitment arm. That is the obligation this file states.

  WHY THERE IS NO `CommitShape` HERE (Spend's Pedersen record): `generate_constraints` contains
  no `BalanceVar`/Pedersen commitment at all. `claim_fee` is a TRANSPARENT public input
  (`ValueVar::new_input`, proof.rs:220) and the outputs are Poseidon note commitments. Forcing
  the Pedersen shape in would be inventing structure. The one place it *would* enter — the
  Swap's blinded `fee_commitment` opening to the same `(asset, amount)` that SwapClaim reveals
  in the clear — is a CROSS-circuit obligation, listed under "does NOT cover" below.
-/
import Penumbra.Circuits.ValueCommit.Basic
import Penumbra.Circuits.Swap.Basic

namespace Penumbra.Circuits.SwapClaim

open Penumbra.Circuits.ValueCommit (AssetId)
/- REUSE (not re-declare) the swap-plaintext vocabulary Swap/Basic.lean already established:
   the swap commitment SwapClaim recomputes (`swap_plaintext_var.commit()`, proof.rs:229) IS
   `Swap.swapCommit`; `note::StateCommitment` is a re-export of `tct::StateCommitment`
   (shielded-pool/src/note.rs:22), so `Swap.StateCommitment` serves both. `Contribution`/`netOf`
   are Swap's per-asset-net vocabulary. Selective `open` so `Swap.PublicInputs`/`PrivateWitness`
   do not collide with ours. -/
open Penumbra.Circuits.Swap (StateCommitment Address Rseed swapCommit Contribution netOf)

/-! ## Opaque carriers not owned by a shared module yet

REVIEW (architecture): `Position`, `Root`, `Nullifier` belong to `Penumbra.Circuits.Tct` /
`NullifierDerivation` once those frames exist; `NoteBlinding` and `noteCommit` to a shared
note module (Output/Basic.lean has its own `noteCommit` over its own witness type — this one
is the same Poseidon function with its inputs pinned, Swap's `swapCommit` idiom). Declared here
only because the shared files are frozen during parallel framing. -/

/-- `tct::Root` — the SCT anchor (`FqVar::new_input`, proof.rs:217). Out of the value frame:
    Merkle inclusion is `Penumbra/Circuits/Tct`'s obligation. -/
axiom Root : Type
/-- `Nullifier` (`NullifierVar::new_input`, proof.rs:218-219). Out of the value frame:
    derivation is `Penumbra/Circuits/NullifierDerivation`'s; double-claim prevention is the
    chain's `check_nullifier_unspent` (action_handler/swap_claim.rs:81). -/
axiom Nullifier : Type
/-- `tct::Position` of the swap commitment (`PositionVar::new_witness`, proof.rs:201-203).
    Value-relevant ONLY through its `epoch`/`block` projections, which pin WHICH batch's
    clearing price the claim may use (proof.rs:255-261). -/
axiom Position : Type
/-- `PositionVar::epoch()` (16 bits). -/
axiom Position.epoch : Position → Nat
/-- `PositionVar::block()` (16 bits). -/
axiom Position.block : Position → Nat
/-- Note blinding `Fq` (`FqVar::new_witness`, proof.rs:213-214); natively derived from the swap
    plaintext's `output_rseeds()` but witnessed FREE in-circuit (no derivation constraint).
    REVIEW: freedom of the blinding is fine for value accounting (it does not enter the
    amount) but means the circuit does not bind the output notes' rseeds to the swap's. -/
axiom NoteBlinding : Type
/-- `NoteVar::commit()` (proof.rs:286, 295): Poseidon note commitment over
    `(address, (amount, asset_id), note_blinding)`. Opaque; only its INPUTS are pinned so a
    collision-resistance/binding assumption can later be stated over exactly this list.
    REVIEW: argument order/arity vs `NoteVar::commit`; the address is one opaque `Address`
    here (its `g_d`, `pk_d`, clue key are folded in, as in Swap). -/
axiom noteCommit : Address → AssetId → Nat → NoteBlinding → StateCommitment

/-! ## The batch swap output data (the published clearing price) -/

/-- Value-relevant projection of `BatchSwapOutputData` (batch_swap_output_data.rs:22-41), as
    allocated by `BatchSwapOutputDataVar::new_input` (150-200). All six amounts are `Amount`s
    (u128) natively, but are allocated IN-CIRCUIT as `U128x128Var` (4 × `UInt64` limbs =
    256 bits, via `Amount → U128x128`, i.e. the amount shifted into the integer half).
    REVIEW (fidelity): the fractional 128 bits of these public inputs are NOT constrained to
    zero in-circuit; the chain always supplies integral values (`check_historical` compares
    against its own stored BSOD), so this is a public-input-integrity assumption, not a
    circuit one. Modelled as plain `Nat` amounts; the shift is `fromAmount`. -/
structure BatchSwapOutputData where
  /-- `delta_1` — total asset_1 input to the batch. -/
  delta1 : Nat
  /-- `delta_2` — total asset_2 input to the batch. -/
  delta2 : Nat
  /-- `lambda_1` — total asset_1 OUTPUT from the batch (for 2⇒1 trades). -/
  lambda1 : Nat
  /-- `lambda_2` — total asset_2 OUTPUT from the batch (for 1⇒2 trades). -/
  lambda2 : Nat
  /-- `unfilled_1` — asset_1 returned unfilled (for 1⇒2 trades). -/
  unfilled1 : Nat
  /-- `unfilled_2` — asset_2 returned unfilled (for 2⇒1 trades). -/
  unfilled2 : Nat
  /-- `trading_pair.asset_1` — via `TradingPairVar::new_variable_unchecked` (same
      no-canonical-ordering caveat as Swap/Basic.lean). -/
  asset1 : AssetId
  /-- `trading_pair.asset_2`. -/
  asset2 : AssetId
  /-- `sct_position_prefix.epoch()` — `FqVar` input, `bit_constrain(_, 16)`. -/
  epoch : Nat
  /-- `sct_position_prefix.block()` — `FqVar` input, `bit_constrain(_, 16)`. -/
  block : Nat

/-! ## Fixed-point arithmetic — `U128x128` as a `Nat` scaled by 2^128 (THE subtle part)

REVIEW (heavily): everything in this section is a transcription of `fixpoint.rs`. A `U128x128`
is a `U256` whose value is `n / 2^128`; here it is the raw `n : Nat` with the invariant
`n < 2^256`. Both the native and the R1CS operations are modelled; they are NOT the same
function at the boundary (overflow), which is exactly why both are here — see
`proRata_circuit_eq_native`. -/

/-- `2^128` — the fixed-point scale. -/
def scale : Nat := 2 ^ 128
/-- `2^256` — the representable bound of a `U128x128` / `U128x128Var`. -/
def limit256 : Nat := 2 ^ 256

/-- `U128x128::from(amount)` / `U128x128Var::from_amount_var` (amount.rs:513-525): the amount's
    128 bits become limbs 2,3 (the integer half), limbs 0,1 are the constant 0. -/
def fromAmount (v : Nat) : Nat := v * scale

/-- `round_down` (native fixpoint.rs:102, R1CS 634) followed by the `U128x128Var → AmountVar`
    conversion (amount.rs:528-537, limbs [2],[3]): drop the fractional word; the integer word IS
    the amount. -/
def roundDown (x : Nat) : Nat := x / scale

/-- Fixed-point product `⌊x·y / 2^128⌋`. Native `checked_mul` (119-154) and R1CS `checked_mul`
    (334-413) both drop the low 128 bits of the 512-bit product (the `x0y0 >> 128` /
    `t0_bits[128..193]` carry) — checked: the two agree on the non-overflowing domain. -/
def fixMul (x y : Nat) : Nat := (x * y) / scale

/-- Fixed-point quotient `⌊x·2^128 / y⌋` for `y ≠ 0` — `stub_div_rem_u384_by_u256` (div.rs:8-25),
    used by BOTH the native `checked_div` (156) and, as the out-of-circuit oracle, the R1CS
    `checked_div` (472-632). -/
def fixDiv (x y : Nat) : Nat := (x * scale) / y

/-! ### The R1CS side — what `BatchSwapOutputDataVar::pro_rata_outputs` actually constrains -/

/-- `U128x128Var::checked_div` (fixpoint.rs:472-632). The oracle supplies `q, r`; the circuit
    enforces `rhs ≠ 0` (485), `r < rhs` (518: `enforce_cmp Less`), and
    `x·2^128 = q·y + r` limb-wise with carries and the top limbs forced to 0 (567-628).
    `q` and `r` are fresh `U128x128Var` witnesses, hence 256-bit by allocation.
    REVIEW: the limb-carry transcription (z0..z6, c1..c5) is trusted to encode exactly this
    integer identity with no field wrap-around; that is a claim about `bit_constrain` widths
    (128/129/130/130/128/64) that a reviewer should re-derive. -/
def DivConstraint (x y q : Nat) : Prop :=
  y ≠ 0 ∧ q < limit256 ∧ ∃ r : Nat, r < y ∧ x * scale = q * y + r

/-- `U128x128Var::checked_mul` (334-413): result is `fixMul` and MUST fit 256 bits — the
    `z6.enforce_equal(zero)` (409) plus `bit_constrain(t4, 64)` (399) make overflow
    UNSATISFIABLE rather than wrapping. -/
def MulConstraint (x y z : Nat) : Prop :=
  z = fixMul x y ∧ z < limit256

/-- `U128x128Var::checked_add` (278-332): limb-wise add, final carry constrained away
    (`bit_constrain(z3_raw + c3, 64)`), so overflow is UNSATISFIABLE. -/
def AddConstraint (x y z : Nat) : Prop :=
  z = x + y ∧ z < limit256

/-- One pro-rata share `delta_j_i / delta_j` as constrained in R1CS
    (batch_swap_output_data.rs:246-258): `delta_j_is_zero := delta_j.is_eq(zero)`;
    divisor := select(is_zero, 1, delta_j); division ALWAYS runs (on a non-zero divisor);
    share := select(is_zero, 0, quotient). So with `delta_j = 0` the share is 0 and the
    division constraint is trivially satisfiable (divisor 1); otherwise it is the real one. -/
def ShareConstraint (di d p : Nat) : Prop :=
  (d = 0 ∧ p = 0) ∨ (d ≠ 0 ∧ DivConstraint (fromAmount di) (fromAmount d) p)

/-- The full R1CS relation of `BatchSwapOutputDataVar::pro_rata_outputs` (230-276) between the
    BSOD, the witnessed inputs `(d1, d2)` = `(delta_1_i, delta_2_i)` and the outputs
    `(l1, l2)` = `(lambda_1_i, lambda_2_i)`:
      lambda_2_i = ⌊ (d1/Δ1)·Λ2 + (d2/Δ2)·U2 ⌋
      lambda_1_i = ⌊ (d1/Δ1)·U1 + (d2/Δ2)·Λ1 ⌋
    with every intermediate a 256-bit fixed-point value (else unsatisfiable).
    REVIEW: the circuit does NOT constrain `d_j ≤ Δ_j` — a share > 1 is representable in-circuit
    and is only excluded by the chain's construction of the batch (Δ_j = Σ_i d_j_i), which this
    file cannot see. See "does NOT cover". -/
def ProRataCircuit (b : BatchSwapOutputData) (d1 d2 l1 l2 : Nat) : Prop :=
  ∃ p1 p2 t21 t22 s2 t11 t12 s1 : Nat,
    ShareConstraint d1 b.delta1 p1 ∧
    ShareConstraint d2 b.delta2 p2 ∧
    -- lambda_2_i = p1·lambda_2 + p2·unfilled_2   (262-264)
    MulConstraint p1 (fromAmount b.lambda2) t21 ∧
    MulConstraint p2 (fromAmount b.unfilled2) t22 ∧
    AddConstraint t21 t22 s2 ∧
    -- lambda_1_i = p1·unfilled_1 + p2·lambda_1   (268-270)
    MulConstraint p1 (fromAmount b.unfilled1) t11 ∧
    MulConstraint p2 (fromAmount b.lambda1) t12 ∧
    AddConstraint t11 t12 s1 ∧
    -- round_down (272-273) then `.into()` AmountVar (275) = `impl From<U128x128Var> for
    -- AmountVar` (amount.rs:528-537): limbs [2],[3] re-packed as the 128-bit amount, no
    -- further constraint
    l1 = roundDown s1 ∧ l2 = roundDown s2

/-! ### The native side — what the chain / planner compute (`unwrap_or_default` semantics) -/

/-- Native `(x / y).unwrap_or_default()`: division by zero → 0, quotient overflow → 0. -/
def nativeDiv (x y : Nat) : Nat :=
  if y = 0 then 0 else (if fixDiv x y < limit256 then fixDiv x y else 0)

/-- Native `(x * y).unwrap_or_default()`: overflow → 0. -/
def nativeMul (x y : Nat) : Nat :=
  if fixMul x y < limit256 then fixMul x y else 0

/-- Native `(a + b).unwrap_or_default()`: overflow → 0 (the WHOLE sum, fixpoint/ops.rs:19-58). -/
def nativeAdd (x y : Nat) : Nat :=
  if x + y < limit256 then x + y else 0

/-- Native `BatchSwapOutputData::pro_rata_outputs` (batch_swap_output_data.rs:47-80), the
    function the chain-side `check_satisfaction` and `SwapPlaintext::output_notes`
    (plaintext.rs:68-69) use. This is the ENTITLEMENT: what a settled swap is owed.
    REVIEW: `.round_down().try_into().expect("rounded amount is integral")` — the integer word
    of a `U128x128` is a `u128`, so the conversion cannot fail; modelled as `roundDown`. -/
def proRataNative (b : BatchSwapOutputData) (d1 d2 : Nat) : Nat × Nat :=
  let p1 := nativeDiv (fromAmount d1) (fromAmount b.delta1)
  let p2 := nativeDiv (fromAmount d2) (fromAmount b.delta2)
  let l2 := nativeAdd (nativeMul p1 (fromAmount b.lambda2)) (nativeMul p2 (fromAmount b.unfilled2))
  let l1 := nativeAdd (nativeMul p1 (fromAmount b.unfilled1)) (nativeMul p2 (fromAmount b.lambda1))
  (roundDown l1, roundDown l2)

/-- **Circuit ⇔ native fidelity of the pro-rata arithmetic (DRAFT — `sorry`).**
    On a SATISFYING assignment the R1CS relation and the native function agree. This is the
    load-bearing `U128x128` obligation. Known boundary divergence, by construction: the native
    code maps any overflow / zero-quotient-overflow to a 0 TERM (`unwrap_or_default`), the
    circuit makes the same event UNSATISFIABLE — so they agree exactly where the circuit
    accepts, and the native side is more permissive (never the reverse).
    REVIEW: (a) the direction "circuit rejects ⇒ native would have returned 0 for that term"
    is what keeps this from being a counterfeiting vector — a term the native code zeroes is
    never one the circuit lets through non-zero; (b) `fixDiv`'s quotient for 128-bit `x, y ≠ 0`
    is `< 2^256` (max `(2^128−1)·2^128`), so the overflow branch of `nativeDiv` is unreachable
    for in-range amounts — but `d_j > Δ_j` is in range and yields a share > 1. -/
theorem proRata_circuit_eq_native
    (b : BatchSwapOutputData) (d1 d2 l1 l2 : Nat)
    (h : ProRataCircuit b d1 d2 l1 l2) :
    (l1, l2) = proRataNative b d1 d2 := by
  sorry  -- PROOF OBLIGATION: unfold both sides; div/mul/add constraints pin each intermediate.

/-! ## The swap plaintext (what the Swap bound and this claim redeems) -/

/-- `SwapPlaintext` as witnessed through `SwapPlaintextVar::new_witness` (proof.rs:194-195).
    Field names are IDENTICAL to `Swap.PrivateWitness`'s plaintext fields so the hoist is
    trivial. REVIEW (architecture): `Swap.PrivateWitness` should embed this structure (it adds
    only `feeBlinding`, which SwapClaim does not witness). Allocation modes / range sites are as
    documented on `Swap.PrivateWitness` (deltas and fee amount via `AmountVar::new_variable` →
    `bit_constrain(_, 128)`; trading pair `new_variable_unchecked`). -/
structure SwapPlaintext where
  /-- `trading_pair.asset_1`. -/
  asset1 : AssetId
  /-- `trading_pair.asset_2`. -/
  asset2 : AssetId
  /-- `delta_1_i` — what the Swap debited of asset_1; the numerator of share 1. -/
  delta1 : Nat
  /-- `delta_2_i` — what the Swap debited of asset_2; the numerator of share 2. -/
  delta2 : Nat
  /-- `claim_fee.amount` — the fee the Swap pre-paid (blinded there, revealed here). -/
  claimFeeAmount : Nat
  /-- `claim_fee.asset_id`. -/
  claimFeeAsset : AssetId
  /-- `claim_address` — the output notes go here (proof.rs:279, 288). -/
  claimAddress : Address
  /-- `rseed` — enters the swap commitment only. -/
  rseed : Rseed

/-! ## The circuit's public inputs and private witness -/

/-- Mirrors `SwapClaimProofPublic` (proof.rs:44-57), allocated `new_input` in source order
    (217-226). Wire order in `verify` (467-501): `anchor ++ nullifier ++ fee.amount ++
    fee.asset_id ++ output_data ++ note_commitment_1 ++ note_commitment_2` field elements.
    Assembled by `check_stateless` (action_handler/swap_claim.rs:30-39) from the tx anchor and
    the transparent `SwapClaimBody`. -/
structure PublicInputs where
  /-- `anchor : tct::Root` — the transaction's anchor. -/
  anchor : Root
  /-- `nullifier : Nullifier` — `body.nullifier`. -/
  nullifier : Nullifier
  /-- `claim_fee : Fee` = `Value { amount, asset_id }`, `ValueVar::new_input` (220): the amount
      is an `AmountVar`, so it is `bit_constrain(_, 128)`ed even as an input. This is the
      TRANSPARENT fee; `SwapClaim::balance()` credits exactly it (action.rs:25-27). -/
  claimFeeAmount : Nat
  claimFeeAsset : AssetId
  /-- `output_data : BatchSwapOutputData` — `body.output_data`, checked against the chain's
      stored BSOD for `(height, trading_pair)` in `check_historical` (56-73). -/
  outputData : BatchSwapOutputData
  /-- `note_commitment_1` — `body.output_1_commitment`. -/
  noteCommitment1 : StateCommitment
  /-- `note_commitment_2` — `body.output_2_commitment`. -/
  noteCommitment2 : StateCommitment

/-- Value-relevant projection of `SwapClaimProofPrivate` (proof.rs:61-78), allocated
    `new_witness` (194-214). OMITTED, owned elsewhere (Spend's scoping pattern):
      state_commitment_proof (Merkle path)  → Penumbra/Circuits/Tct
      nk (and the nullifier derivation)     → Penumbra/Circuits/NullifierDerivation
      ak, ivk ↔ claim_address binding       → spend-authority (proof.rs:246-250) -/
structure PrivateWitness where
  /-- `swap_plaintext : SwapPlaintext` (194-195). -/
  swapPlaintext : SwapPlaintext
  /-- `state_commitment_proof.commitment()` witnessed SEPARATELY as `claimed_swap_commitment`
      (197-199); it is what the Merkle and nullifier arms consume, and is forced equal to the
      recomputed plaintext commitment (229-230). -/
  swapCommitment : StateCommitment
  /-- `state_commitment_proof.position()` (201-203). -/
  position : Position
  /-- `lambda_1 : Amount` (211) — the CLAIMED asset_1 output; `AmountVar::new_witness` →
      `bit_constrain(_, 128)`. -/
  lambda1 : Nat
  /-- `lambda_2 : Amount` (212) — the CLAIMED asset_2 output. -/
  lambda2 : Nat
  /-- `note_blinding_1 : Fq` (213). -/
  noteBlinding1 : NoteBlinding
  /-- `note_blinding_2 : Fq` (214). -/
  noteBlinding2 : NoteBlinding

/-! ## The deployed relation vs. what we read off it -/

/-- The R1CS relation of the DEPLOYED `SwapClaimCircuit::generate_constraints`, abstract. This is
    the `DeployedR1CS.Satisfies` that `Penumbra.Snark.groth16_verify_implies_witness` hands us a
    witness for; the circuit-vs-model gap lives exactly here (see Snark/Contract/DeployedR1CS.lean).
    REVIEW: to be replaced by the extracted constraint system once the arkworks R1CS is reified. -/
axiom Satisfies : PublicInputs → PrivateWitness → Prop

/-- The value arm of `generate_constraints` (proof.rs:190-301), read off the Rust (DRAFT), one
    clause per constraint site in circuit order. The non-value arms — Merkle inclusion
    (233-239), nullifier derivation (242-243), ivk/transmission-key binding (246-250) — are
    deliberately NOT here; see `PrivateWitness`. -/
def ValueSpec (pub : PublicInputs) (wit : PrivateWitness) : Prop :=
  -- range: every `AmountVar` is bit-constrained to 128 bits at allocation (amount.rs:204):
  -- plaintext deltas + fee (via SwapPlaintextVar), claimed lambdas (211-212), public fee (220)
  wit.swapPlaintext.delta1 < 2 ^ 128 ∧ wit.swapPlaintext.delta2 < 2 ^ 128 ∧
  wit.swapPlaintext.claimFeeAmount < 2 ^ 128 ∧
  wit.lambda1 < 2 ^ 128 ∧ wit.lambda2 < 2 ^ 128 ∧
  pub.claimFeeAmount < 2 ^ 128 ∧
  -- swap-commitment integrity: `claimed_swap_commitment.enforce_equal(&swap_commitment)` (229-230)
  --   — the SAME `Swap.swapCommit` argument list the Swap circuit committed to
  wit.swapCommitment =
    swapCommit wit.swapPlaintext.asset1 wit.swapPlaintext.asset2
      wit.swapPlaintext.delta1 wit.swapPlaintext.delta2
      wit.swapPlaintext.claimFeeAmount wit.swapPlaintext.claimFeeAsset
      wit.swapPlaintext.claimAddress wit.swapPlaintext.rseed ∧
  -- fee consistency: `claimed_fee_var.enforce_equal(&swap_plaintext_var.claim_fee)` (253)
  pub.claimFeeAmount = wit.swapPlaintext.claimFeeAmount ∧
  pub.claimFeeAsset = wit.swapPlaintext.claimFeeAsset ∧
  -- clearing-price height: the swap commitment's SCT position must sit in the batch's block
  --   `output_data.block_within_epoch.enforce_equal(position.block())` (256-258),
  --   `output_data.epoch.enforce_equal(position.epoch())` (259-261)
  pub.outputData.block = wit.position.block ∧
  pub.outputData.epoch = wit.position.epoch ∧
  -- trading pair: `output_data.trading_pair.enforce_equal(&swap_plaintext.trading_pair)` (264-266)
  pub.outputData.asset1 = wit.swapPlaintext.asset1 ∧
  pub.outputData.asset2 = wit.swapPlaintext.asset2 ∧
  -- output amounts integrity: `pro_rata_outputs(delta_1_i, delta_2_i)` then
  --   `computed_lambda_j_i.enforce_equal(&lambda_j_i_var)` (269-275)
  ProRataCircuit pub.outputData wit.swapPlaintext.delta1 wit.swapPlaintext.delta2
    wit.lambda1 wit.lambda2 ∧
  -- output note integrity (278-298): note 1 = (claim_address, lambda_1 @ asset_1, blinding_1),
  --   note 2 = (claim_address, lambda_2 @ asset_2, blinding_2); each `enforce_equal` its input
  pub.noteCommitment1 =
    noteCommit wit.swapPlaintext.claimAddress wit.swapPlaintext.asset1 wit.lambda1
      wit.noteBlinding1 ∧
  pub.noteCommitment2 =
    noteCommit wit.swapPlaintext.claimAddress wit.swapPlaintext.asset2 wit.lambda2
      wit.noteBlinding2

/-! ## Contributions (Swap's `Contribution` / `netOf` vocabulary; `true` = credit) -/

/-- What the claim actually CREATES: the two output notes' values, as credits. These never
    touch the transaction balance (the chain inserts the commitments directly), which is why
    they are stated as a contribution list of their own rather than through `SwapClaim::balance`. -/
def claimedOutputs (wit : PrivateWitness) : List Contribution :=
  [ (wit.swapPlaintext.asset1, true, wit.lambda1),
    (wit.swapPlaintext.asset2, true, wit.lambda2) ]

/-- What the settled batch ENTITLES the swap to: the native `pro_rata_outputs` applied to the
    plaintext's own deltas, on the plaintext's own pair (`SwapPlaintext::output_notes`,
    plaintext.rs:65-92). -/
def entitlement (b : BatchSwapOutputData) (p : SwapPlaintext) : List Contribution :=
  [ (p.asset1, true, (proRataNative b p.delta1 p.delta2).1),
    (p.asset2, true, (proRataNative b p.delta1 p.delta2).2) ]

/-- What the claim CREDITS to the transaction balance: `SwapClaim::balance() = body.fee.value()`
    (action.rs:25-27; plan.rs:126-136 "only the pre-paid fee is contributed"). Sign is solid:
    `Balance::from(Value)` is positive, no negation on the path. -/
def feeCredit (pub : PublicInputs) : List Contribution :=
  [ (pub.claimFeeAsset, true, pub.claimFeeAmount) ]

/-- The fee the Swap pre-paid, as bound into the swap commitment. -/
def feeOwed (p : SwapPlaintext) : List Contribution :=
  [ (p.claimFeeAsset, true, p.claimFeeAmount) ]

/-! ## The obligation -/

/-- **SwapClaim value accounting (DRAFT — `sorry`; for cryptographer review, not a result).**

    Informally: an R1CS-satisfying SwapClaim (i) satisfies the transcribed value spec,
    (ii) outputs, per asset, EXACTLY the value the settled batch entitles the swap to — the
    native pro-rata share of `BatchSwapOutputData` applied to the deltas the Swap itself
    committed — no more; and (iii) credits back to the transaction balance exactly the fee the
    Swap pre-paid. Stated with Swap's PER-ASSET NET (`netOf`), not slot-wise, for the same
    reason as there: the circuit does not exclude `asset1 = asset2`, under which the two notes
    aggregate.

    Solid (read, not guessed): the fee sign and path; the two notes' assets/address come from
    the plaintext, their amounts from the witnessed lambdas; the range sites; the height/pair
    pinning of WHICH BSOD applies.
    Draft: `Satisfies` is abstract; every `U128x128` definition (the pro-rata arithmetic) is
    a transcription and `proRata_circuit_eq_native` is itself unproven; `swapCommit`/`noteCommit`
    are opaque.

    What this does NOT cover (deferred or out of reach of this frame):
    * BATCH-LEVEL conservation — the circuit does NOT enforce `delta_j_i ≤ delta_j`; that
      `delta_j = Σ_i delta_j_i` over the block's swaps and hence `Σ_i lambda_j_i ≤ lambda_j +
      unfilled_j` is the chain's BSOD construction + swap-commitment/SCT-position binding — an
      aggregate obligation this per-action file cannot state. NAME IT FIRST in any review.
    * BSOD authenticity — `check_historical` compares `body.output_data` to chain state; the
      circuit trusts its public input.
    * Double-claim — nullifier derivation + `check_nullifier_unspent`; Merkle inclusion of the
      swap commitment; ivk ↔ claim_address binding.
    * Binding / collision resistance of `swapCommit` (linking THIS plaintext to the Swap that
      debited it) and of `noteCommit`.
    * The Swap's blinded `fee_commitment` opening to the same `(asset, amount)` revealed here
      (cross-circuit; the only place Spend's `CommitShape` would enter).
    * Round-down dust: each claimant loses < 1 unit per asset to `round_down` — under-pays,
      the safe direction; not a counterfeiting concern but a conservation-slack one.
    * Lifting through Groth16 (`Snark.groth16_verify_implies_witness` + a `Satisfies → ValueSpec`
      bridge, Swap's `swap_valueAccounted_snark` pattern) and `deserialize_compressed_unchecked`. -/
theorem swapClaim_valueAccounted (pub : PublicInputs) (wit : PrivateWitness)
    (h : Satisfies pub wit) :
    ValueSpec pub wit ∧
    (∀ a : AssetId,
      netOf (claimedOutputs wit) a = netOf (entitlement pub.outputData wit.swapPlaintext) a) ∧
    (∀ a : AssetId,
      netOf (feeCredit pub) a = netOf (feeOwed wit.swapPlaintext) a) := by
  sorry  -- PROOF OBLIGATION: value-arm soundness of the deployed SwapClaim R1CS,
         -- then `proRata_circuit_eq_native` for (ii) and the fee clauses for (iii).

end Penumbra.Circuits.SwapClaim
