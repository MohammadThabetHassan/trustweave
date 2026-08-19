# Assurance Gap Inventory

## Purpose

This inventory records the assurance baseline before the 0.2.3 enhancement cycle. It distinguishes what TrustWeave already demonstrates from work that can be verified inside the repository, controls that require an owner and an external platform, and capabilities the project deliberately excludes.

The inventory is an engineering planning record, not a claim that a listed future control already exists.

## Implemented baseline

| Area | Existing evidence | Residual limit |
| --- | --- | --- |
| Product boundary | Local declarations and already-recorded metadata only; explicit non-executing documentation and regression coverage. | No runtime inspection, enforcement, discovery, or live-system assessment. |
| Parsing and contracts | Strict typed parsers, packaged schemas, schema/runtime conformance, and safe JSON/YAML input handling. | Supplied declarations can still be incomplete or unauthenticated. |
| Deterministic evidence | Stable local decision builders, fixed-time controls, local integrity attestations, reproducibility helper, and schema-backed artifacts. | Local hash relationships are unsigned and not external provenance. |
| Quality engineering | Ruff, strict Mypy, Bandit, property tests, 95% branch coverage, isolated wheel/source checks, and a repository reality gate. | These checks cannot prove absence of all defects. |
| Mutation diagnostic | Twelve-module hosted mutation gate with score, parity, and triage controls. | The selected scope is bounded and does not prove global security. |
| Release controls | SHA-pinned workflows, separate build/publish jobs, OIDC trusted publishing, TestPyPI rehearsal, clean installation, annotated tags, and GitHub releases. | Current 0.2.2 package release does not claim authenticated package provenance. |

## Measurable repository work for 0.2.3

| Gap | Planned control | Completion evidence |
| --- | --- | --- |
| Compatibility claims are distributed across prose and tests | Versioned compatibility source, generated policy pages, and exact contract validation. | A local validator proves agreement with package metadata, CI matrix, CLI surface, schemas, and retained reader fixtures. |
| Deterministic outputs lack a curated public reference corpus | Synthetic golden evidence corpus and a check-only verifier. | A clean temporary regeneration matches approved inventory, canonical digests, schemas, paths, and expected failures. |
| Threat model is narrative-first | Machine-readable threat-to-control-to-test traceability source and generated review map. | The validator rejects orphaned IDs, missing controls, missing tests, or missing residual limits. |
| Parser/output resource bounds are not uniformly documented as contracts | Source-audited, generous file/structure/output budgets with fail-closed errors and boundary tests. | Positive/boundary/over-limit tests plus published limits and clean reproduction record. |
| Release provenance readiness is not independently consumer-verifiable | TestPyPI-first official PyPI attestation verification procedure and synthetic verifier fixtures. | Observed TestPyPI package provenance verification before a production claim. |
| Assurance documentation is not centrally discoverable | Public assurance map, README navigation, contributor checklist, and documentation contracts. | Reality and strict-site checks verify discoverability and truthful wording. |

## Owner-controlled settings and evidence

| Control | Required owner action | Evidence required before a claim |
| --- | --- | --- |
| Trusted-publisher identity | Verify index configuration for owner, repository, workflow, environment, and release authorization. | Real TestPyPI and PyPI workflow records for the exact tag/version. |
| Package attestations | Approve TestPyPI-first attestation enablement and production activation after rehearsal. | Clean-environment official consumer verification of exact published artifact and expected repository identity. |
| Secret scanning, push protection, and Dependabot settings | Confirm repository settings and operational response model. | Publicly observable configured state or owner-approved evidence; no inference from documentation. |
| Scorecard, badges, or external assessment | Review scope, permissions, retention, and published report. | Real report that supports each displayed result. |

## Deliberately excluded scope

TrustWeave will not add runtime interception, live agent execution, MCP connections, tool invocation, model calls, credential access, automatic upload, auto-merge behavior, third-party target scanning, secret collection, or a hosted service as part of this cycle. These are separate operational products with different threat, privacy, identity, and availability requirements.

## Review rule

A future assurance claim must move from the measurable or owner-controlled table into the implemented baseline only after source, deterministic tests, release evidence, and stated residual limits are all present. If any element is missing, the correct outcome is an explicit non-claim.
