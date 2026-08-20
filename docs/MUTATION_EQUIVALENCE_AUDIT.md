# Mutation-equivalence audit

## Scope and outcome

This record accompanies the final fourteen-module `mutmut` inventory. It is a **source-level equivalence audit**, not a security certification. Every retained survivor was reviewed after the previously misclassified approval-boundary mutation was reproduced with a reachable declared-chain input.

> The approval-boundary mutant `trustweave.chain.x__advance_state__mutmut_8` is **not equivalent**. A public regression now proves that `fail_closed=False` does not approve confidential data before an external action, and the focused mutation run reports that mutant as killed.

The post-correction full run contains **122 survivors**. Each has an exact source diff, an individual rationale, and a recorded proof or behavioral assertion in [`mutation-survivor-triage-v1.json`](mutation-survivor-triage-v1.json). The audit found **no retained survivor that changes a reachable finding ID or count, severity, risk state, policy decision, approval state, classification propagation, path-containment result, digest, fingerprint, schema selection, validation result, exit code, artifact content, or reproducible byte output**. The 15 survivors from the newly scoped policy-weakening classifier are restricted to unreachable dictionary-default variants, equivalent strict-contract predicates, and equivalent path-splitting forms.

## Review method

Each survivor was checked against the following decision rule. A record remains `equivalent` only where the mutated expression is a runtime no-op, a falsy-value substitution with identical use, a codec-name alias, a static type cast, a diagnostic-context-only input, or an unreachable/redundant branch under the validated public contract. Any potentially reachable reviewer-visible or security-relevant difference must instead receive a behavioral regression and be killed.

| Reviewed family | Survivors | Result of review |
| --- | ---: | --- |
| Chain parsing, rendering, and traversal state | 11 | Validation-context arguments, repeated mapping checks after successful type proof, and structurally unreachable duplicate-state handling. The observable non-fail-closed approval mutant was removed by a public regression. |
| CI coordination and artifact publication | 24 | Stage-local dead state, redundant prerequisites protected by prior dependency validation, and recovery branches proven unreachable or behavior-preserving. SARIF containment guards retain independent POSIX and Windows defenses. |
| Configuration | 5 | Validation-context values and an inclusive maximum that no valid fourteen-stage vocabulary can reach. |
| Evidence and attestation | 5 | Case-insensitive UTF-8 aliases, redundant logical-name predicates after separator checks, and subject-binding checks that cannot make malformed bindings verify. |
| Canonical findings | 9 | Validation-context values, runtime-no-op `typing.cast` expressions, and falsy option substitutions with identical filtering behavior. |
| Models and policy predicates | 17 | Runtime-no-op casts, default arguments equal to library defaults, identical first-suggestion selection, and bounds outside every validated taxonomy index. |
| Policy review | 3 | Subject fallbacks where internally produced findings never contain an alternate subject key. |
| Policy-weakening classifier | 15 | Strict parsed-policy invariants make the changed mapping defaults, non-empty-string predicates, and approval-field split variants unreachable or observationally identical; exact proofs are in the inventory. |
| Risk lifecycle and decision documents | 25 | Validation-context values, case-insensitive UTF-8 aliases, and ISO-8601 `Z` handling that is equivalent on the supported Python 3.11+ baseline. |
| SARIF | 8 | Runtime-no-op casts, case-insensitive UTF-8 aliases, and a URI tiebreaker unreachable because equal rule/message pairs arise only within one source-kind artifact. |
| **Total retained equivalents** | **122** | **All retain individual exact diffs and code-level rationales in the tracked triage inventory.** |

## Gate relationship

The hosted mutation gate independently requires exact survivor identifier parity, exact normalized-diff parity, no duplicate IDs, zero untriaged records, zero `needs_regression` records, non-empty rationales, internally consistent totals, and a score of at least 95%. This audit does not weaken or bypass those controls.

## Limitations

Mutation testing is a bounded diagnostic for the configured high-risk modules. It does not prove that TrustWeave is secure, establish real-world agent behavior, or replace ordinary tests, static analysis, compatibility jobs, review, or owner release authorization.
