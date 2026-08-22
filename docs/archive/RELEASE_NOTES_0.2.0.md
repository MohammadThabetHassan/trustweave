# TrustWeave 0.2.0 Unpublished Audit Record

> **Audit status:** Annotated tag `v0.2.0` targets `7232fe3a23d92f50a693903c0a6b7cb92d0a1426`, was created during pre-publication verification, was never published to PyPI, and has no GitHub Release. It remains immutable unpublished audit evidence and must not be moved, reused, or published from. The corrected current release target is [`0.2.1`](RELEASE_NOTES_0.2.1.md).

## Summary

TrustWeave 0.2.0 hardens the local, declarative evidence workflow around strict input validation, risk-decision lifecycle behavior, historical bundle compatibility, deterministic CI publication, and mutation-test evidence. The release remains deliberately local-first: it does not execute agents, models, tools, MCP servers, shell commands from declarations, or network actions.

| Area | 0.2.0 outcome |
| --- | --- |
| Historical bundle evidence | v1alpha1 bundles receive semantic validation with explicit safe behavior for authentic v0.1.1 evidence; v1alpha2 validation remains strict. |
| Risk lifecycle | Baselines and suppressions expire at `expires_at <= reviewed_at`; malformed fingerprints, duplicate decisions, and boundary timestamps fail closed. |
| CI coordination | The fourteen supported stages have typed configuration, staged atomic publication, safe artifact paths, reproducible provenance checks, and deterministic summaries. |
| Evidence integrity | Attestations bind logical names, exact local files, stable digests, source revision, and strict v1alpha3 subject/predicate structure. |
| Findings and SARIF | Canonical finding metadata is bounded and immutable; SARIF output has strict input validation, deterministic ordering, stable fingerprints, and active-risk filtering. |
| Mutation evidence | The twelve-module run killed 6,044 of 6,140 mutants (98.44%). The exact 96-survivor inventory preserves diffs, classifications, and code-level equivalence proofs; the hosted gate enforces exact survivor-identifier and normalized-diff parity. |

## Security and correctness hardening

The release strengthens validation at public artifact boundaries rather than attempting runtime enforcement. The v1alpha1 bundle reader now rejects malformed legacy evidence instead of accepting a structurally plausible but semantically inconsistent document. Authentic v0.1.1 evidence remains readable under an explicit historical contract, while current v1alpha2 documents keep their strict schema and semantic checks.

Risk reviews now enforce the exact expiry invariant that a decision is no longer active when its expiry timestamp equals the review timestamp. Decision documents reject malformed fingerprint forms, duplicate fingerprints, invalid timestamps, invalid severities, and non-conforming fields. Baseline creation and risk review preserve deterministic active-state, severity, provenance, and lifecycle counters.

The staged CI coordinator validates all configured artifacts before publication, creates nested output destinations safely, and keeps failure behavior atomic. Configuration names for bundle comparison inputs are `baseline_bundle` and `candidate_bundle`; the abbreviated legacy names are not accepted.

## Compatibility and migration impact

The major contract updates are additive where safe and strict where ambiguity would undermine local evidence. Users moving from 0.1.1 should review the detailed [migration guide](MIGRATION_GUIDE_0.2.0.md) before updating automation or stored reviewer-decision documents.

| Prior input or behavior | 0.2.0 behavior | Required action |
| --- | --- | --- |
| v1alpha1 historical bundle | Accepted only when it meets the authentic historical semantic contract. | Validate retained evidence and regenerate malformed artifacts from their original source where possible. |
| `baseline` / `candidate` configuration fields | Replaced by `baseline_bundle` / `candidate_bundle`. | Rename configuration fields. |
| risk-review and decision drafts | v1alpha2 contracts enforce stricter fingerprint, provenance, timestamp, and duplicate-decision rules. | Migrate documents using the supplied schema and validate before use. |
| local CI stage selection | The complete supported list contains fourteen stages. | Use documented names only and satisfy their declared path dependencies. |

## Verification evidence

The following evidence is recorded for this source target. It is local verification evidence, not a claim that hosted workflows, publishing, release signing, or external deployment has completed.

| Check | Recorded status |
| --- | --- |
| Branch coverage gate | Passed in the maintained test suite at or above the enforced 95% branch threshold. |
| Twelve-module mutation run | 6,044 killed / 6,140 generated / 96 survived = 98.44% killed. |
| Survivor inventory | 96 exact mutant IDs, zero untriaged records, zero `needs_regression` records, source diffs, and code-level rationales preserved in [`mutation-survivor-triage-v1.json`](../mutation-survivor-triage-v1.json). |
| Reproducibility | Existing staged-CI byte-identical evidence remains recorded in [REPRODUCIBILITY.md](../REPRODUCIBILITY.md). |
| Static and contract checks | The normal quality command, strict schemas, and repository reality check remain required before owner review. |

## Known limitations and current acceptance blocker

TrustWeave remains a local deterministic review tool. It does not prove that a deployed agent, policy, approval workflow, model, MCP server, tool, or external system behaves as declared. A passing result does not constitute a security certification, authorization decision, remediation, signature, transparency-log assertion, or production release.

The current 98.44% mutation measurement satisfies the numeric threshold and the local survivor-triage requirement: the preserved inventory has zero untriaged and zero `needs_regression` classifications. Merge readiness requires the hosted mutation workflow on the exact reviewed SHA to report the same 6,044/6,140/96 result, exact survivor-identifier parity, exact normalized-diff parity, and a green status alongside every other required local and hosted check.

## Owner-controlled next steps

This historical record preserves the 0.2.0 hardening evidence. For every current merge or release action, the owner must use [OWNER_RELEASE_CHECKLIST_0.2.1.md](OWNER_RELEASE_CHECKLIST_0.2.1.md); no version tag, package publication, release creation, artifact signing, or merge is authorized by this audit record.
