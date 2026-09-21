/-
  Axiom census — the highest-value thing to copy from Ironwood (Meta/AxiomCheck.lean, Apache/MIT).
  Port `assert_axioms` verbatim: assert an UPPER BOUND on a declaration's trusted base rather than
  pinning an exact `#print axioms` string. Permitted set for THIS project:
      { propext, Classical.choice, Quot.sound }  ∪  { the ONE Groth16 AGM assumption }
  Reject `sorryAx` always; reject `native_decide` unless explicitly permitted (fixtures only).
  Also police `@[implemented_by]`/`@[extern]` compiled-body overrides in repo-owned modules.

  TODO: copy the actual `assert_axioms` elaborator + CensusCheck endpoint coverage from
  /steam/rotko/ironwood/Zcash/Meta/AxiomCheck.lean and adapt the ambient-package allowlist.
-/
namespace Penumbra.Meta
end Penumbra.Meta
