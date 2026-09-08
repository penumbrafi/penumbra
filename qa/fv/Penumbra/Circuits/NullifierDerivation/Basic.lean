/-
  ╔════════════════════════════════════════════════════════════════════════════════════════╗
  ║  DRAFT FOR CRYPTOGRAPHER REVIEW — SKELETON, NOT A PROOF.                               ║
  ║  The obligation below is `sorry`. Every structure field and every clause of            ║
  ║  `NullifierSpec` is a *transcription* of the arkworks R1CS code by a non-cryptographer  ║
  ║  and MUST be checked against the Rust before anything downstream is trusted.           ║
  ║  `-- REVIEW:` marks the places where the transcription is least certain.               ║
  ╚════════════════════════════════════════════════════════════════════════════════════════╝

  Penumbra NullifierDerivation circuit — nullifier-correctness soundness obligation (frame).

  STYLE: mirrors zcash/ironwood (Apache-2.0 / MIT), `Zcash/Circuits/Action/Spec.lean`
  ("nullifier integrity: `nf_old = Extract((PRF(nk, ρ) + ψ) • K + cm_old)`") — a
  circuit-independent `Spec : PublicInputs → Witness → Prop`, one clause per in-circuit
  constraint site, each citing the Rust line it mirrors; the deployed R1CS relation is the
  abstract `Satisfies` axiom (as in `Spend/Basic.lean`), and the circuit ↔ spec boundary is an
  EXPLICIT hypothesis in the `_snark` variant (as in `Swap/Basic.lean`), never hidden.
  Penumbra's nullifier is a Poseidon377 hash of an Fq triple, not Orchard's `PRF ∘ (•K)`; only
  ironwood's SHAPE is reused.

  SOURCE OF TRUTH (penumbra repo, read 2026-09-09):
    crates/core/component/shielded-pool/src/nullifier_derivation.rs
        NullifierDerivationProofPublic (28-35), NullifierDerivationProofPrivate (39-42),
        NullifierDerivationCircuit::generate_constraints (89-106), verify (165-209)
    crates/core/component/sct/src/nullifier.rs
        NULLIFIER_DOMAIN_SEP (44-46), Nullifier::derive (69-78, native),
        NullifierVar::derive (147-165, in-circuit), NullifierVar alloc (109-126)
    crates/core/keys/src/keys/nullifier.rs      NullifierKey(pub Fq), NullifierKeyVar alloc (18-35)
    crates/crypto/tct/src/r1cs.rs               PositionVar::new_variable (36-61),
                                                StateCommitmentVar::new_variable (289-315)
    crates/core/component/shielded-pool/src/spend/proof.rs:185-186
                                                the SAME `NullifierVar::derive` gadget, on chain

  WHY THIS MATTERS FOR COUNTERFEITING (the double-spend link):
    A note is spent by revealing its nullifier; the chain rejects a nullifier it has already
    seen. Value conservation across the ledger therefore rests on the nullifier being a
    DETERMINISTIC function of the note: if one note could be spent under two different
    nullifiers, it could be spent twice, i.e. value would be created. The obligation of this
    file is exactly that a satisfying witness forces
        nullifier = hash_3(DOMAIN_SEP, nk, note_commitment, position)
    — the nullifier is pinned by (nk, note commitment, position), nothing else.

  SCOPE — READ BEFORE TRUSTING THE COROLLARY (the brief's blind spot):
    nullifier_derivation.rs:78-81 states this circuit is CLIENT-SIDE ONLY, not verified on
    chain, and that `nk` is NOT linked in-circuit to the address of the note behind
    `note_commitment`. So THIS circuit alone does not give "one nullifier per note": a
    different `nk` yields a different nullifier for the same note. The on-chain double-spend
    obligation lives in the Spend circuit's nullifier arm (spend/proof.rs:185-186), which calls
    the SAME `NullifierVar::derive` gadget and separately binds nk → ivk → address → note.
    `Spend/Basic.lean`'s header delegates "nullifier, nk, position" to this directory: the
    `derive` / `NullifierSpec` defined here is what Spend's nullifier arm will consume.
    `nullifier_deterministic` below is therefore deterministic-FOR-FIXED-nk; nk-uniqueness per
    note is Spend's (or a sibling's) obligation, not this file's.
-/
import Penumbra.Snark.Contract.DeployedR1CS

namespace Penumbra.Circuits.NullifierDerivation

/-! ## Abstract carriers

A nullifier, a note commitment and a nullifier key are all BLS12-377 scalar-field elements
(`decaf377::Fq`), NOT group elements, so `ValueCommit.Element` is the wrong carrier; a field
type is minted here. REVIEW: collapse into `Penumbra.Arithmetic` once Fq is modelled. -/

/-- `decaf377::Fq` — the BLS12-377 scalar field, over which every circuit is defined. -/
axiom Fq : Type
/-- The canonical embedding `Nat → Fq` used for the position:
    native `(u64::from(pos)).into()` (sct/nullifier.rs:76), in-circuit
    `Boolean::le_bits_to_fp_var(&bits[0..48])` (tct/r1cs.rs:51). REVIEW: these agree only
    because the circuit enforces `bits[48..] = 0`; see `PublicInputs.position`. -/
axiom Fq.ofNat : Nat → Fq
/-- `NULLIFIER_DOMAIN_SEP = Fq::from_le_bytes_mod_order(blake2b(b"penumbra.nullifier"))`
    (sct/nullifier.rs:44-46). In-circuit it is a `FqVar::new_constant` (sct/nullifier.rs:153). -/
axiom nullifierDomainSep : Fq
/-- `poseidon377::hash_3 domain_sep (a, b, c)`. Opaque.
    REVIEW (THE fidelity item of this file): the native `poseidon377::hash_3`
    (sct/nullifier.rs:74) and the in-circuit `poseidon377::r1cs::hash_3` (sct/nullifier.rs:154)
    must agree as functions Fq⁴ → Fq — same round constants, MDS, rate/capacity, domain-separator
    slot — for `NullifierSpec` to describe the deployed circuit. That agreement is its own
    obligation (compare `Swap.balanceCommit`'s `Balance::commit` vs `BalanceVar::commit` note). -/
axiom hash3 : Fq → Fq → Fq → Fq → Fq

/-- `Nullifier::derive` (sct/nullifier.rs:69-78), argument order `(nk, state_commitment, pos)`:
    `hash_3(NULLIFIER_DOMAIN_SEP, (nk.0, cm.0, u64(pos).into()))`. The same order is used by
    `NullifierVar::derive` (sct/nullifier.rs:157-161). -/
noncomputable def derive (nk noteCommitment : Fq) (position : Nat) : Fq :=
  hash3 nullifierDomainSep nk noteCommitment (Fq.ofNat position)

/-! ## Public instance and private witness -/

/-- Mirrors `NullifierDerivationProofPublic` (nullifier_derivation.rs:28-35). Allocation order
    in `generate_constraints` is nullifier, note_commitment, position (lines 94-99), and
    `verify` feeds Groth16 `nullifier ++ note_commitment ++ position` (lines 173-195) — same
    order; a layout mismatch there would make `hbridge` below vacuous. -/
structure PublicInputs where
  /-- `nullifier : Nullifier` = `Nullifier(pub Fq)`, allocated `NullifierVar::new_input` →
      `FqVar::new_input` (sct/nullifier.rs:120-122). -/
  nullifier : Fq
  /-- `note_commitment : tct::StateCommitment` (an `Fq`), allocated
      `StateCommitmentVar::new_input` → `FqVar::new_input` (tct/r1cs.rs:299-305).
      Opaque here: the circuit never opens it (that is the Spend circuit's note-commitment
      integrity arm); it enters the hash as a field element only. -/
  noteCommitment : Fq
  /-- `position : tct::Position` (a `u64`), allocated `PositionVar::new_input` →
      `UInt64::new_variable`, then `bits[48..]` enforced `false` and the hashed field element
      rebuilt from `bits[0..48]` (tct/r1cs.rs:46-52). Modelled as an unbounded `Nat`; the
      48-bit bound is a CONCLUSION of `NullifierSpec`, not an assumption on the type.
      REVIEW: the native side passes `u64::from(pos)` — 64 bits — so native/in-circuit
      derivations agree exactly on positions `< 2^48`, which every real `tct::Position` is. -/
  position : Nat

/-- Mirrors `NullifierDerivationProofPrivate` (nullifier_derivation.rs:39-42). -/
structure Witness where
  /-- `nk : NullifierKey` = `NullifierKey(pub Fq)`, allocated `NullifierKeyVar::new_witness` →
      `FqVar::new_witness` (keys/nullifier.rs:30-32). A bare witnessed field element: nothing
      in THIS circuit ties it to any key hierarchy or address (nullifier_derivation.rs:78-81). -/
  nk : Fq

/-! ## The deployed relation vs. what we read off it -/

/-- The R1CS relation of the DEPLOYED `NullifierDerivationCircuit::generate_constraints`,
    abstract. This is the `DeployedR1CS.Satisfies` that `Penumbra.Snark.groth16_verify_implies_witness`
    hands us a witness for; the circuit-vs-model gap lives exactly here
    (see Snark/Contract/DeployedR1CS.lean).
    REVIEW: to be replaced by the extracted constraint system once the arkworks R1CS is reified. -/
axiom Satisfies : PublicInputs → Witness → Prop

/-- `generate_constraints` read off the Rust (DRAFT), one clause per constraint site:
    1. position range — `PositionVar` allocation side effect `bits[48..] = 0`
       (tct/r1cs.rs:48-50);
    2. nullifier integrity — `NullifierVar::derive(nk, position, note_commitment)`
       `conditional_enforce_equal(claimed_nullifier, Boolean::TRUE)` (nullifier_derivation.rs:102-103).
       The condition is the constant `TRUE`, so the check is unconditional — the same arm in
       Spend (spend/proof.rs:186) uses plain `enforce_equal`.
    There are no other constraints in this circuit. -/
def NullifierSpec (pub : PublicInputs) (wit : Witness) : Prop :=
  pub.position < 2 ^ 48 ∧
  pub.nullifier = derive wit.nk pub.noteCommitment pub.position

/-! ## The obligation -/

/-- **Nullifier-derivation soundness (DRAFT — for cryptographer review, not yet proven).**

    Any witness satisfying the deployed NullifierDerivation R1CS forces the public `nullifier`
    to be exactly `hash_3(DOMAIN_SEP, nk, note_commitment, position)` — the deterministic
    derivation of the note's nullifier from the witnessed nullifier key and the public
    (note commitment, position). Informally: a proof cannot reveal a nullifier that is not
    the nullifier of the named note under the witnessed key.

    Double-spend link: the chain's nullifier set is what stops a note being spent twice, and
    that defence is only as good as the nullifier being pinned by the note. This theorem is
    the "pinned" half: for fixed `(nk, note_commitment, position)` there is exactly one
    nullifier the circuit accepts. That `nk` is itself pinned to the note (so no second key
    yields a second nullifier for the same note) is NOT this circuit's job — see the SCOPE
    note in the header; the on-chain Spend circuit binds it.

    Solid: the argument order `(nk, cm, position)` and the domain separator, both read off
    `Nullifier::derive` and `NullifierVar::derive` side by side; the unconditional equality.
    Draft: `Satisfies` is abstract; `hash3` is opaque and its native/in-circuit agreement is
    a `REVIEW` item; the 48-bit position clause is dropped from this conclusion (it lives in
    `NullifierSpec`) because the correctness statement does not need it. -/
theorem nullifier_isDerived (pub : PublicInputs) (wit : Witness)
    (h : Satisfies pub wit) :
    pub.nullifier = derive wit.nk pub.noteCommitment pub.position := by
  sorry  -- PROOF OBLIGATION: nullifier-arm soundness of the deployed NullifierDerivation R1CS.

/-- **Determinism for a fixed key (corollary of `nullifier_isDerived`; inherits its `sorry`).**
    Two satisfying instances naming the same `(nk, note_commitment, position)` reveal the same
    nullifier — the same note cannot yield two nullifiers under one key. Proven structurally
    from `nullifier_isDerived` by rewriting; nothing about `hash3` is used. -/
theorem nullifier_deterministic
    (pub₁ pub₂ : PublicInputs) (wit₁ wit₂ : Witness)
    (h₁ : Satisfies pub₁ wit₁) (h₂ : Satisfies pub₂ wit₂)
    (hnk : wit₁.nk = wit₂.nk)
    (hcm : pub₁.noteCommitment = pub₂.noteCommitment)
    (hpos : pub₁.position = pub₂.position) :
    pub₁.nullifier = pub₂.nullifier := by
  rw [nullifier_isDerived pub₁ wit₁ h₁, nullifier_isDerived pub₂ wit₂ h₂, hnk, hcm, hpos]

/-- **Through the SNARK (DRAFT — `sorry`).** The same statement lifted to a verifying Groth16
    proof, via `Snark.groth16_verify_implies_witness`, under an EXPLICIT bridge hypothesis
    `hbridge` that the deployed R1CS's satisfaction relation implies `NullifierSpec` on the
    decoded public input / witness. That bridge is ironwood's `actionSpec_iff_specPost` seam
    and is the SPEC-vs-DEPLOYED-CIRCUIT gap (`Snark.DeployedR1CS` header) — kept as a
    hypothesis, never discharged silently.
    REVIEW: `decodePub` is the arkworks `to_field_elements` layout of `verify`
    (nullifier ++ note_commitment ++ position); a wrong layout makes `hbridge` vacuous. -/
theorem nullifier_isDerived_snark
    (cs : Penumbra.Snark.DeployedR1CS)
    (decodePub : cs.PublicInput → PublicInputs) (decodeWit : cs.Witness → Witness)
    (hbridge : ∀ x w, cs.Satisfies x w → NullifierSpec (decodePub x) (decodeWit w))
    (vk : cs.VerifyingKey) (x : cs.PublicInput) (π : cs.Proof)
    (hverify : cs.Verify vk x π = true) :
    ∃ w : cs.Witness,
      (decodePub x).nullifier =
        derive (decodeWit w).nk (decodePub x).noteCommitment (decodePub x).position := by
  sorry  -- PROOF OBLIGATION: groth16_verify_implies_witness ∘ hbridge ∘ (NullifierSpec).2.

/-! ## Residual REVIEW items (not expressible above yet)

  * "Distinct notes ⇒ distinct nullifiers" (no two notes share a nullifier) is NOT stated: it
    is collision resistance of `hash3` on its `(nk, cm, position)` slots — computational, and
    it belongs with the `εNullifier` term of `Security/Ledger/Capstone.lean`, not with R1CS
    soundness. When `hash3` gets a collision-resistance assumption, state it over exactly the
    argument list of `derive`.
  * `nk` is a free witness here (nullifier_derivation.rs:78-81). The property that the
    revealed nullifier is the nullifier of the note's OWNER key is the Spend circuit's
    (spend/proof.rs:185-186 with the ivk/address arm), which should import `derive` from this
    file rather than re-transcribe it.
  * `Proof::deserialize_compressed_unchecked` in `verify` (nullifier_derivation.rs:171) —
    point validity / proof malleability. Out of knowledge-soundness scope; belongs to
    `Snark/TrustBoundary/Groth16.lean` ("knowledge-soundness only").
  * `Fq.ofNat` on positions ≥ 2^48 is never reached by a satisfying witness (range clause),
    but the native `Nullifier::derive` accepts any `u64`; native and circuit derivations
    diverge only on positions no real `tct::Position` takes.
-/

end Penumbra.Circuits.NullifierDerivation
