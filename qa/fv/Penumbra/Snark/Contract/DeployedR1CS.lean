/-
  The circuit ↔ SNARK seam (Ironwood's "deployed constraint system", retargeted to R1CS/QAP).
  The circuit layer produces a `DeployedR1CS`; the Groth16 adapter turns a verifying proof into
  a satisfying witness; the Ledger layer turns a satisfying witness into value conservation.

  THE SPEC-vs-IMPLEMENTATION GAP lives here: one must justify that the QAP fed to the Groth16
  lemma is the QAP of Penumbra's *actually-deployed* arkworks circuit. Documented, not hidden.
-/
namespace Penumbra.Snark

/-- Abstract handle to a deployed R1CS/QAP over BLS12-377's scalar field. -/
structure DeployedR1CS where
  Witness      : Type
  PublicInput  : Type
  VerifyingKey : Type
  Proof        : Type
  Verify       : VerifyingKey → PublicInput → Proof → Bool
  Satisfies    : PublicInput → Witness → Prop

end Penumbra.Snark
