# qa/fv — formal verification of no-counterfeiting for Penumbra

**Mission.** Produce a machine-checked Lean 4 proof that Penumbra's shielded pool
cannot be *undetectably* counterfeited — i.e. that committed value can never
diverge from declared value balance except with negligible probability, bounded
by an explicit sum of cryptographic hardness terms. The artifact is a Lean
development whose theorems are checked by the Lean kernel, resting on a small,
*named and audited* set of assumptions — not on human review of the Rust alone.

**Status: OPENING DRAFT / SCAFFOLD.** The module tree, the top property, and the
trust boundary are laid out; every proof obligation is currently an explicit
`sorry` or a named axiom. Nothing here is proved yet. This branch exists so the
community — working with strong agents — can discharge the obligations one at a
time against a hard gate (see `AGENTS.md`).

This work **adapts the methodology of Tal Derei, Sean Bowe, and the Project
Tachyon / zkSecurity teams** (Zcash Ironwood & Ragu formal verification). We copy
their *architecture* and *discipline*; we do not copy their SNARK subtree, because
Penumbra uses a different proof system (Groth16, not Ironwood's IPA/Bulletproofs).

---

## The property

The capstone theorem (`Penumbra/Security/Ledger/Capstone.lean`) is a *supply
integrity* bound in the style of Ironwood's **balance integrity**:

> For any efficient (algebraic) adversary producing an accepted bundle, the
> probability that the net committed value differs from the net declared value
> is at most `ε_dlog + Σ (statistical terms)`, each term negligible for the
> deployed curves and field.

Undetectable counterfeiting is exactly the event this bounds: because blocks
commit to the full contents of every transaction (including its proofs), an
implementation bug *below the trust boundary* can only ever produce **detectable**
counterfeiting — history can be replayed through corrected software. The formal
target is therefore the *undetectable* case, which is the one suited to proof.

---

## Architecture (bottom → top)

Mirrors `zcash/ironwood`'s `Zcash/` tree and `tachyon-zcash/ragu`'s `qa/fv/Ragu/`.

| Layer | Path | What it establishes |
|---|---|---|
| 0. SNARK floor | `Penumbra/Snark/TrustBoundary/Groth16.lean` | adapter to Bailey–Miller `is_sound`: *proof verifies ⇒ QAP satisfied*, under AGM. **Cited, not reproved.** |
| 1. Verifier fingerprint | `Penumbra/Snark/Contract/DeployedR1CS.lean` (+ `Fingerprint/`) | the math↔software seam. A symbolic MSM ("fingerprint") *defines* the verifier in Lean; `extraction/` derives it from the real arkworks verifier. This is where spec-fidelity is pinned. |
| 2. Circuit soundness | `Penumbra/Circuits/<Action>/` | per-action, via **Clean**: *QAP satisfied ⇒ the action's relation holds and value is accounted*. One dir per action (Spend, Output, Swap, SwapClaim, Convert, DelegatorVote, NullifierDerivation) + `ValueCommit`, `Tct`. |
| 3. Value ledger | `Penumbra/Security/Ledger/` | the value model + the capstone `penumbra_supplyIntegrity_measure_le`. |
| — Trust ledger | `Penumbra/Meta/` | the `assert_axioms` **census**: every named assumption the proof rests on, enumerated and checked in CI. |

The **fingerprint boundary** (layer 1) is the single most important idea we take
from Tal Derei's work: prove soundness about a symbolic object, then show the
deployed code reproduces that object, rather than trying to reason about Rust.

---

## Source repositories (what we take, and its license)

Everything below is public. Attribution and license compliance are mandatory;
adapted files must carry the upstream copyright notice.

| Repo | Role here | License |
|---|---|---|
| **`zcash/ironwood`** — Zcash Ironwood proof (Tal Derei, Sean Bowe, et al.) | the **architecture template**: `Zcash/{Circuits,Snark,Security,Meta,Arithmetic,Common}`, the axiom-census discipline, `book/src/formal-verification/clean-boundary.md`. | Apache-2.0 / MIT |
| **`tachyon-zcash/ragu`** → `qa/fv/` | the **cleanest Clean reference**: `Ragu/Circuits` (Clean R1CS soundness), `Ragu/Fingerprint` + `PolynomialFingerprint` (the boundary in code), `extraction/` (Rust→Lean fingerprint derivation). Our `qa/fv` layout is modeled on it. | (see repo) |
| **`Verified-zkEVM/clean`** — Clean, zkSecurity | the **Lean 4 eDSL + verification framework for ZK circuits**. Layer 2 is written in Clean. Pin a specific rev (ragu pins a Lean-4.30 rev; reconcile with our toolchain). | (see repo) |
| **`BoltonBailey/formal-snarks-project`** — Bailey–Miller | the **Groth16 knowledge-soundness floor** (IACR 2023/656; USENIX Security 2024). Penumbra uses Type-III Groth16 over BLS12-377, so this is our layer-0 citation. | Apache-2.0 |
| **`daira/CompElliptic`** — Daira-Emma Hopwood | elliptic-curve support (used by ragu's fv). | (see repo) |
| **`leanprover-community/mathlib4`** | the mathematical library everything builds on. Pin the toolchain-matched rev. | Apache-2.0 |
| **`penumbra-zone/penumbra`** (this repo) | the **subject**: the arkworks circuits, `ValueCommitment`, and the deployed Groth16 verifier that `extraction/` fingerprints. | Apache-2.0 |

Blog references: `tachyon.z.cash/blog/ironwood-verification-complete/`,
`tachyon.z.cash/blog/folding-tachyon-with-ragu/`, `blog.zksecurity.xyz/posts/clean/`.

---

## Highest counterfeiting risk (audit + prove first)

From an initial pass over Penumbra's arkworks circuits (`crates/…`), the value
paths most likely to hide a counterfeiting bug, in priority order:

1. **Amount range.** The 2^128 range check is enforced via
   `AmountVar::AllocVar → bit_constrain … 128` (an `enforce_equal` side effect).
   Obligation: prove *every* value-commitment path routes through it.
2. **Convert / SwapClaim fixed-point arithmetic** (`U128x128`): rate-multiply and
   pro-rata output must be range-sound (no wrap creating value).
3. **Multi-asset generator independence**: a named random-oracle assumption at the
   trust boundary (distinct asset value generators are independent).

These are the first Clean circuit obligations to attempt.

---

## Layout of this directory

```
qa/fv/
  README.md              ← this map
  AGENTS.md              ← how community + agents contribute (the workflow + the gate)
  lakefile.toml          ← deps-free build that compiles the skeleton today
  lakefile.with-deps.toml← target build: Clean + CompElliptic + Bailey–Miller + mathlib
  lean-toolchain         ← pinned Lean version (reconcile to the Clean/mathlib rev)
  Penumbra.lean          ← import root
  Penumbra/
    Snark/               ← layer 0 (Groth16 adapter) + layer 1 (fingerprint/DeployedR1CS)
    Circuits/            ← layer 2, per-action Clean soundness
    Security/Ledger/     ← layer 3, value model + capstone
    Meta/                ← the axiom census
  extraction/            ← (to add) Rust crate: derive the verifier fingerprint from penumbra's code
```

## Immediate tasks

1. **Toolchain reconciliation.** Ironwood pins Lean 4.30 (its Clean rev); Bailey–
   Miller uses 4.30/4.33; mathlib must match. Pick one target, pin Clean +
   CompElliptic + formal-snarks + mathlib to it in `lakefile.with-deps.toml` +
   `lake-manifest.json`, then `lake exe cache get && lake build` to a compiling
   skeleton (with `sorry`s).
2. **Port the axiom census** (`Meta/`) from Ironwood; wire it into CI so the set
   of named assumptions is always visible and can only grow deliberately.
3. **Add `extraction/`** — the Rust crate that emits Penumbra's Groth16 verifier
   fingerprint, adapting ragu's `qa/fv/extraction`.
4. **First circuit:** model the **Spend** action as a QAP and discharge its
   soundness obligation in Clean (simplest value-bearing action).

Nothing is proved until `lake build` is green **with an empty `sorry` set and a
reviewed axiom census.** See `AGENTS.md` for the contribution gate.
