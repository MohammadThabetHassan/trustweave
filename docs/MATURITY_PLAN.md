# Maturity Plan

## Purpose

This plan identifies the evidence required for TrustWeave to improve release quality without expanding beyond its local, deterministic, non-executing product contract. Completion requires a versioned implementation, a deterministic test, a reproducible verification record, or an explicit limitation. It does not authorize a merge, tag, signing operation, or package publication.

> **Rating discipline.** A repository must not claim a maturity rating that its recorded acceptance controls do not meet. Local tests and documentation cannot manufacture independent adoption, external review, signing, or production security evidence.

## Verified current controls

| Area | Recorded control | Residual boundary |
|---|---|---|
| Core workflow | Local manifest/policy scan, synthetic scenarios, v1alpha2 bundle diff, policy review, trace and MCP metadata review, chain review, risk review, SARIF, unsigned statement, and attestation verification. | Evidence concerns only supplied declarations and pre-recorded metadata; it does not establish runtime behavior or enforcement. |
| Quality engineering | Ruff, strict mypy, Bandit, property-based tests, **95% branch coverage**, isolated wheel checks, fixed-epoch wheel reproducibility, dependency audit, SBOM generation, and Python 3.11/3.13 compatibility jobs. | These controls do not replace human review or validate external deployment. |
| Schema and compatibility | Byte-synchronized source/package schemas, exact current-output conformance, v1alpha2 bundle/diff/risk-review contracts, bounded historical v1alpha1 compatibility, and reality-check documentation markers. | Historical evidence is not silently redefined; migration means regenerating current evidence. |
| Distribution | PyPI `0.1.1` is published. Source is prepared for `0.2.0`, but it is neither tagged nor published. | Publication, tagging, signing, and release creation remain owner-controlled. |
| Mutation diagnostic | Twelve-module Linux mutmut run: 6,063 generated, 4,787 killed, 1,276 survived, 0 untested, timed out, or suspicious; **78.95%** killed. | The result is below the required ≥90% acceptance target and survivors are untriaged. |

## Open 9.8 acceptance blocker

The expanded mutation analysis is the remaining stated 9.8 acceptance blocker. The audit requires a ≥90% killed score over the configured twelve-module scope and zero untriaged survivors. The recorded 78.95% result does **not** meet that requirement. Documentation must preserve this limitation until new measured evidence, survivor triage, and corresponding regression tests demonstrate otherwise.

| Required next evidence | Completion condition |
|---|---|
| Survivor classification | Every surviving mutant is killed by a meaningful regression, proven equivalent with a repository-visible rationale, or otherwise handled by an owner-approved policy that does not weaken tests or coverage. |
| Reproducible re-run | A fresh twelve-module mutmut run uses the checked-in `pyproject.toml` scope and retains exact counts, tool version, platform limitation, selected test set, and commands. |
| Acceptance result | The measured killed score is ≥90% and no survivor remains untriaged. |
| Release verification | Strict local gate, package build, distribution metadata validation, reproducibility proof, local attestation verification, and hosted checks pass on the same PR head. |

## Compatibility and documentation discipline

A required-field or semantic output change receives a new versioned artifact contract. Current generation emits `trustweave.dev/bundle/v1alpha2`, `trustweave.dev/bundle-diff/v1alpha2`, and `trustweave.dev/risk-review/v1alpha2`. Historical v1alpha1 schema resources remain packaged rather than being redefined. The repository reality check verifies source/package schema synchronization, producer-linked current artifact schemas, real-output conformance, and current documentation markers.

## External evidence that repository work cannot create

| Missing external proof | Responsible path | Do not fabricate |
|---|---|---|
| Independent reviewer feedback | Invite review of synthetic examples and record resolved, non-sensitive feedback. | Testimonials, stars, users, or adoption metrics. |
| Authenticated provenance | Design signing identity, verification, retention, and failure handling only with owner authorization. | “Signed,” “verified,” or “tamper-proof” labels based on local hashes. |
| Production release proof | Owner-authorized TestPyPI/PyPI publication and release workflow on an approved tag. | A publication claim based on a local build or green CI. |

## Non-negotiable boundaries

TrustWeave must not execute tools, call models, connect to MCP servers, access credentials, inspect third-party systems, scan live infrastructure, upload results, auto-merge updates, or claim runtime security. A rejected scope expansion is a successful result when it preserves this contract.
