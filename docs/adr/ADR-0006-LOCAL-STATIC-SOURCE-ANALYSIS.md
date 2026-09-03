# ADR-0006: Local Static Source Analysis

## Status

Accepted for the additive `trustweave.dev/code-discovery/v1alpha1` contract. This decision
narrows a published safety boundary and required an explicit maintainer decision under
`docs/ROADMAP.md`, "Maintainer decisions that require explicit authorization".

## Context

Every TrustWeave input before this decision was a document the reviewer wrote or exported
by hand: a manifest, a policy, a saved snapshot, an already-provided `tools/list` payload.
That kept the boundary simple, and it also placed the product after the step users cannot
take. Deciding which sources are trusted, and which tools carry which action class, is the
analysis itself. A team able to fill in a manifest accurately has already done the work the
engine then checks.

The failure mode this leaves open is silent and common: a tool is added to the codebase and
never added to the manifest. Nothing in the product could see it. The manifest stayed
internally consistent, the scan stayed green, and the declared trust boundary no longer
described the system.

Two published statements stood against closing that gap.
`docs/PRODUCT_CONTRACT.md` listed "analyze untrusted repositories" among the explicit safety
boundaries, and `docs/ROADMAP.md` recorded that the static MCP inventory performs "no
discovery, connection, or action-class inference". The second is the sharper constraint:
action-class inference was excluded deliberately, not by omission.

## Decision

TrustWeave analyzes local Python source with the standard library `ast` module, and the
boundary is restated rather than removed.

| Topic | Decision |
|---|---|
| Execution | The analyzer parses. It never imports, compiles, installs, executes, or resolves the dependencies of the analyzed project. No code from the analyzed tree runs in the TrustWeave process. |
| Scope | The reviewer names a local path. Nothing is fetched, cloned, or resolved from a remote. A symbolic link out of the analyzed root is refused rather than followed. |
| Trust | Trust is never inferred. Every source in an emitted draft carries the literal `unknown`, and no code path can produce another value. |
| Action class | Inferred as a **proposal**, from a bounded, versioned symbol catalog, recorded with the evidence that produced it. A proposal is never an authorization and never a security verdict. |
| Refusal | Ambiguity produces `unknown` with a reason code, not a best guess. Dynamic dispatch, unresolved callees, non-literal arguments, missing bodies, and exhausted budgets all refuse. |
| Severity | Every `TW-CODE-*` finding is `review`. A static inference must not present itself as a graded verdict, and must not gate a pipeline as though it were one. |
| Draft validity | The emitted manifest draft deliberately does not validate. `unknown` and `REVIEW_REQUIRED` sit outside the accepted vocabularies, so `parse_manifest` rejects the draft until a reviewer resolves it. A draft that parsed would eventually be fed to `scan` as though it had been reviewed. |
| Determinism | Output is ordered and integer-valued. Coverage is reported in basis points by floor division, so no floating-point value reaches an artifact. |

The `analyze untrusted repositories` commitment in `docs/PRODUCT_CONTRACT.md` is replaced by
a precise statement of what the analyzer does and does not do, rather than left standing
while the code contradicts it.

## Consequences

A reviewer can now be told what their agent can reach, and where the declaration and the
code disagree. Declaration coverage becomes a number rather than an assumption.

The cost is a real widening of the input surface: TrustWeave now reads code it did not
previously read. The mitigations are the bounded intake in `code_sources.py`, the refusal
discipline in `code_analysis.py`, and the uniform `review` severity. The analyzer is
deliberately conservative about discovery: a public function that is not decorated as a tool
or bound into a tools list is not reported as one, because enumerating every function would
inflate a draft manifest with things that are not tools.

The `risk.py` artifact-contract row was **not** added. Registering the contract there would
make `TW-CODE-*` findings eligible for `risk-check --fail-on`, which would let a static
inference block a pipeline. That trade-off contradicts "proposes, never authorizes" and is
deferred as a separate decision.

Two vocabularies for the same idea now coexist: `mcp-scaffold` marks reviewer-required
fields `REVIEW_REQUIRED`, while this contract uses `unknown` for trust and refused action
classes and keeps `REVIEW_REQUIRED` for free-text placeholders. This is recorded as a known
inconsistency to be resolved by aligning `mcp-scaffold`, not by making either draft validate.
