/-
  Multi-asset decaf377 Pedersen value commitment — the object all seven circuits commit through.
      commit(balance, blinding) = Σ_assets (±amount_a · G_a) + blinding · H
  with  G_a = decaf377.encode_to_curve (poseidon377.hash_1 domain asset_id_a),  H = VALUE_BLINDING_GENERATOR.

  Source of truth: penumbra crates/core/asset/src/balance.rs `Balance::commit`,
  circuit form in crates/core/asset/src/balance/commitment.rs.
-/
namespace Penumbra.Circuits.ValueCommit

/-- decaf377 group element (abstract; to be tied to `Penumbra.Arithmetic`). -/
axiom Element : Type
/-- Asset id. -/
axiom AssetId : Type
/-- Per-asset value generator G_a. -/
axiom valueGenerator : AssetId → Element

/-- **Assumption (random-oracle):** the per-asset generators are independent, i.e. no nontrivial
    discrete-log relation among the `valueGenerator a` and `H`. Reduces to poseidon377 + decaf377
    `encode_to_curve` behaving as a random oracle. This is the MULTI-ASSET counterfeiting arm that
    single-asset Zcash has no counterpart for; it is a named trust-boundary assumption. -/
axiom generator_independence : True  -- TODO: state as a no-DL-relation predicate over Element.

/-- **Proof obligation (range):** every committed amount is < 2^128. In the Rust this is enforced
    by `AmountVar::AllocVar` calling `bit_constrain _ 128` (whose `enforce_equal` is a CS side
    effect). The obligation for us: EVERY value entering a commitment is allocated through that
    path, never as a raw field element. Verified partially by inspection 2026-09; must be proven. -/
theorem amount_range_enforced : True := by trivial  -- TODO: real statement + proof.

end Penumbra.Circuits.ValueCommit
