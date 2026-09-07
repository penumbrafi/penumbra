-- Penumbra supply-integrity formalization — single import root.
-- Status: SCAFFOLD. Not yet build-verified (Lean toolchain not installed in this session).
-- Template: zcash/ironwood (Apache/MIT). SNARK floor: BoltonBailey/formal-snarks-project (Apache-2.0).
import Penumbra.Snark.TrustBoundary.Groth16
import Penumbra.Snark.Contract.DeployedR1CS
import Penumbra.Circuits.ValueCommit.Basic
import Penumbra.Security.Ledger.Balance
import Penumbra.Security.Ledger.Capstone
