-- Penumbra supply-integrity formalization — single import root.
-- Status: SCAFFOLD (builds green on Lean 4.27; obligations are `sorry` by design).
-- Template: zcash/ironwood (Apache/MIT). SNARK floor: BoltonBailey/formal-snarks-project (Apache-2.0).
import Penumbra.Snark.TrustBoundary.Groth16
import Penumbra.Snark.Contract.DeployedR1CS
import Penumbra.Circuits.ValueCommit.Basic
-- per-action circuit frames (value-accounting obligations, DRAFT statements for review)
import Penumbra.Circuits.Spend.Basic
import Penumbra.Circuits.Output.Basic
import Penumbra.Circuits.Swap.Basic
import Penumbra.Security.Ledger.Balance
import Penumbra.Security.Ledger.Capstone
