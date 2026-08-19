# Assurance Gap Inventory

## Purpose

This inventory records the assurance baseline after the unreleased 0.2.3 enhancement cycle. It distinguishes what TrustWeave demonstrates in the source tree from controls that still require an owner and an external platform, and capabilities the project deliberately excludes.

The inventory is an engineering record, not a publication, authenticated-provenance, or external-adoption claim. `0.2.2` remains the current public package release until an approved 0.2.3 tag and release record exist.

## Implemented baseline

| Area | Existing evidence | Residual limit |
| --- | --- | --- |
| Product boundary | Local declarations and already-recorded metadata only; explicit non-executing documentation and regression coverage. | No runtime inspection, enforcement, discovery, or live-system assessment. |
| Parsing and contracts | Strict typed parsers, packaged schemas, schema/runtime conformance, and safe JSON/YAML input handling. | Supplied declarations can still be incomplete or unauthenticated. |
| Deterministic evidence | Stable local decision builders, fixed-time controls, local integrity attestations, reproducibility helper, and schema-backed artifacts. | Local hash relationships are unsigned and not external provenance. |
| Quality engineering | Ruff, strict Mypy, Bandit, property tests, 95% branch coverage, isolated wheel/source checks, and a repository reality gate. | These checks cannot prove absence of all defects. |
| Mutation diagnostic | Twelve-module hosted mutation gate with score, parity, and triage controls. | The selected scope is bounded and does not prove global security. |
| Release controls | SHA-pinned workflows, separate build/publish jobs, OIDC trusted publishing, TestPyPI rehearsal, clean installation, annotated tags, and GitHub releases. | Current 0.2.2 package release does not claim authenticated package provenance. |

## Implemented 0.2.3 candidate assurance work

| Former gap | Implemented control | Present evidence and remaining limit |
| --- | --- | --- |
| Compatibility claims were distributed across prose and tests | Versioned compatibility source, support/deprecation policy, and exact contract validation. | A local validator proves agreement with candidate package metadata, CI matrix, CLI surface, schemas, and retained reader fixtures. `0.2.2` remains the separate public release record. |
| Deterministic outputs lacked a curated public reference corpus | Synthetic golden evidence corpus and a check-only verifier. | Temporary regeneration matches approved inventory, canonical digests, schemas, paths, and expected failures. The synthetic corpus does not prove live-system behavior. |
| Threat model was narrative-first | Machine-readable threat-to-control-to-test traceability source and generated review map. | The validator rejects orphaned IDs, missing controls, missing tests, missing evidence, or missing residual limits. It does not establish external assessment coverage. |
| Parser/output resource bounds were not uniformly documented as contracts | Source-audited file/structure/chain budgets and a fail-closed SARIF result ceiling with boundary tests. | Published limits and regression tests restrict local evidence work; they are not a hosted-service performance guarantee. |
| Release provenance readiness was not independently consumer-verifiable | TestPyPI-first PyPI project-attestation generation in both trusted-publishing workflows, an official exact-file verification procedure, and a workflow-control validator. | Generation is configured but no `0.2.3` package has been published or independently verified; observed TestPyPI expected-repository verification remains required before a production claim. |
| Assurance documentation was not centrally discoverable | Public assurance map, README/site navigation, contributor checklist, and reality-gate documentation contracts. | Strict documentation and reality checks validate discoverability and truthful pre-release wording. |

## Owner-controlled settings and evidence

| Control | Required owner action | Evidence required before a claim |
| --- | --- | --- |
| Trusted-publisher identity | Verify index configuration for owner, repository, workflow, environment, and release authorization. | Real TestPyPI and PyPI workflow records for the exact tag/version. |
| Package attestations | Dispatch the configured TestPyPI workflow from an approved annotated tag, preserve the exact file identity, and approve production only after the TestPyPI observation passes. | Clean-environment official consumer verification of the exact published artifact and expected repository identity. |
| Secret scanning, push protection, and Dependabot settings | Confirm repository settings and operational response model. | Publicly observable configured state or owner-approved evidence; no inference from documentation. |
| Scorecard, badges, or external assessment | Review scope, permissions, retention, and published report. | Real report that supports each displayed result. |

## Deliberately excluded scope

TrustWeave will not add runtime interception, live agent execution, MCP connections, tool invocation, model calls, credential access, automatic upload, auto-merge behavior, third-party target scanning, secret collection, or a hosted service as part of this cycle. These are separate operational products with different threat, privacy, identity, and availability requirements.

## Review rule

A future assurance claim must move from the measurable or owner-controlled table into the implemented baseline only after source, deterministic tests, release evidence, and stated residual limits are all present. If any element is missing, the correct outcome is an explicit non-claim.
