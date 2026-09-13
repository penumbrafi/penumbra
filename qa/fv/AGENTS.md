# AGENTS.md — how to contribute to qa/fv (humans + agents)

This proof is meant to be built **obligation by obligation**, by contributors and
by strong AI agents, against a gate that cannot be talked past. A model can write
fluent mathematics that is subtly wrong; on a *counterfeiting* proof a confident
"verified" that is false is worse than no proof. So the rule is simple:

> **The Lean kernel decides. Not the author, not the reviewer, not the agent.**

## The unit of work: one obligation

Every task is a single, named proof obligation from the map in `README.md`
(e.g. "Spend circuit: QAP satisfied ⇒ value accounted", or "amount range: every
commit path routes through `bit_constrain 128`"). Pick one, discharge it, open a
PR. Do not batch unrelated obligations.

## The gate (a PR is mergeable only if ALL hold)

1. **`lake build` is green** for the touched targets.
2. **No proof holes.** Zero `sorry`, `admit`, `Admitted`, `give_up`, `native_decide`
   in changed files. A proof that admits its goal is not a proof.
   - Enforced locally by the zish `verify` feat (proof-oracle mode) and in CI.
3. **The axiom census did not silently grow.** `Penumbra/Meta/` enumerates every
   named assumption. Any *new* axiom must be (a) named, (b) justified in the PR
   with the cryptographic reason it is a boundary assumption, (c) reviewed by a
   maintainer. Closing an obligation by inventing an axiom is a rejection, not a
   solution.
4. **The fingerprint boundary is respected.** Do not reason about the Rust
   directly. Soundness is proved about the symbolic verifier fingerprint
   (`Snark/Contract/DeployedR1CS`); faithfulness of the deployed code to the
   fingerprint lives in `extraction/` and is its own, separately-reviewed claim.
5. **Reductions are computable data, not existence claims** (adapted from ragu's
   `assert_computable` convention): a security reduction returns the *breaking
   data*; "no break exists" is never assumed as a hypothesis. This blocks the two
   ways a security theorem goes vacuous.

If you cannot close an obligation, submit the partial proof **with the `sorry`
clearly at the open goal** and a note on what is blocking — as a draft PR, never
merged. That is useful; a green build hiding a `sorry` is not.

## Workflow for an agent

Grounding first, then Lean, then the gate:

1. **Read the references** for the analogous obligation before writing:
   `tachyon-zcash/ragu` `qa/fv/Ragu/Circuits/*` (Clean patterns) and
   `zcash/ironwood` `Zcash/Circuits/*`. Adapt, don't reinvent.
2. **Read the subject code**: the arkworks circuit in `penumbra` this obligation
   is about. State the relation faithfully; a wrong relation that type-checks is
   the failure mode.
3. **Write the Clean/Lean** for the one obligation.
4. **Gate locally**: `lake build`; then run the proof oracle on changed files,
   e.g. `verify lean < file.lean` (or, once wired, `verify lake .` for the whole
   project). Iterate on real kernel errors, not on self-assessment.
5. **Open a PR** including the **axiom-census diff** and the source files you
   adapted (with upstream attribution).

The zish/zash toolchain supports this loop — `web` for grounding, tool-using
`agent solo` / `team` workers that read the code and run the checker, `verify`
as the kernel gate — but the workflow is tool-agnostic. Any agent that respects
the gate can contribute.

## What agents (and humans) must NOT do

- Close an obligation with `sorry`/`admit` and a green top-level build.
- Add an `axiom` to make a proof go through without flagging it in the census.
- Prove a theorem about the *wrong* relation (always cross-check the relation
  against the arkworks circuit and the reference proof).
- Reason about the deployed Rust outside the fingerprint boundary.
- Reproduce the Groth16 soundness proof — cite Bailey–Miller instead.

## Honest scope

Ironwood — *one* shielded pool — took three expert teams over a month with Clean
and its authors. Penumbra is comparable. Agents genuinely accelerate the grind
(drafting circuit lemmas, discharging obligations, gathering evidence), but two
things stay human: **deciding what the theorems should say**, and **judging
whether the fingerprint is faithful to the deployed code**. Treat any agent
output on those two as a proposal for cryptographer review, never a result.
