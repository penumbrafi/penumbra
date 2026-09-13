/-
  Ledger value model: per-transaction net value vs declared value balance, tied to the binding
  signature. Analog of Ironwood's Ledger/Balance.lean + Ledger/Value.lean.

  Binding signature (penumbra crates/core/transaction/src/transaction.rs::binding_verification_key):
  sum every action's balance_commitment + fee commitment into one decaf377 element; the binding
  sig verifies iff that residual is a commitment to ZERO value (blinding·H only). That is the glue
  enforcing Σ value = 0 across a transaction.
-/
namespace Penumbra.Security.Ledger

/-- Signed, multi-asset net value of a transaction (asset_id ↦ signed amount). Abstract for now. -/
axiom NetValue : Type
/-- Declared value balance carried in the transaction. -/
axiom vBalance : Type

/-- Conservation predicate, per transaction. The Capstone bounds the measure of its NEGATION. -/
axiom txConserves : NetValue → vBalance → Prop

end Penumbra.Security.Ledger
