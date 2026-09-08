/-
  Trust boundary: Groth16 (Type III, asymmetric pairing — the arkworks/BLS12-377 variant)
  knowledge-soundness under the Algebraic Group Model.

  We do NOT axiomatize this outright. It is discharged by the Bailey–Miller formalization
  `FormalSnarksProject.SNARKs.Groth16TypeIII.Soundness.is_sound`, whose statement is:
  in the symbolic AGM, any prover whose proof satisfies the Groth16 Type III verification
  equation yields a witness for which the QAP divisibility relation holds
  (over an abstract `Field F`, generic over the QAP polynomials u/v/w).

  This file provides the thin adapter from that lemma to our `DeployedR1CS` seam.

  RESIDUAL ASSUMPTIONS (must be listed in every Security endpoint's `assert_axioms`):
   * AGM: the prover is algebraic.
   * knowledge-soundness only, NOT simulation-extractability ⇒ no proof non-malleability.
-/
import Penumbra.Snark.Contract.DeployedR1CS
-- import FormalSnarksProject.SNARKs.Groth16TypeIII.Soundness

namespace Penumbra.Snark

/-- Adapter target: a verifying Groth16 proof over a deployed R1CS yields a satisfying witness.
    TODO: instantiate `formal-snarks` `is_sound` at BLS12-377's scalar field and bridge its
    QAP-divisibility conclusion to `DeployedR1CS.Satisfies`. -/
theorem groth16_verify_implies_witness
    (cs : DeployedR1CS) (vk : cs.VerifyingKey) (x : cs.PublicInput) (π : cs.Proof) :
    cs.Verify vk x π = true → ∃ w : cs.Witness, cs.Satisfies x w := by
  sorry  -- PROOF OBLIGATION: reduce to FormalSnarksProject … is_sound via the QAP of `cs`.

end Penumbra.Snark
