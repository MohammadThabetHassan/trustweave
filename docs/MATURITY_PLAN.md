# Maturity Plan

## Purpose

This plan identifies the evidence required for TrustWeave to improve release quality without expanding beyond its local, deterministic, non-executing product contract. Completion requires a versioned implementation, a deterministic test, a reproducible verification record, or an explicit limitation. It does not authorize a merge, tag, signing operation, or package publication.

> **Rating discipline.** A repository must not claim a maturity rating that its recorded acceptance controls do not meet. Local tests and documentation cannot manufacture independent adoption, external review, signing, or production security evidence.

## Verified current controls

| Area | Recorded control | Residual boundary |
|---|---|---|
| Core workflow | Local manifest/policy scan, synthetic scenarios, v1alpha3 policy-aware bundle diff, policy review, trace and MCP metadata review, chain review, risk review, SARIF, unsigned statement, and attestation verification. | Evidence concerns only supplied declarations and pre-recorded metadata; it does not establish runtime behavior or enforcement. |
| Quality engineering | Ruff, strict mypy, Bandit, property-based tests, **95% branch coverage**, isolated wheel checks, fixed-epoch wheel reproducibility, dependency audit, SBOM generation, and Python 3.11/3.13 compatibility jobs. | These controls do not replace human review or validate external deployment. |
| Schema and compatibility | Byte-synchronized source/package schemas, exact current-output conformance, v1alpha2 bundle and risk-review contracts, a v1alpha3 policy-aware bundle-diff contract, bounded historical v1alpha1/v1alpha2 diff-reader compatibility, and reality-check documentation markers. | Historical evidence is not silently redefined; migration means regenerating current evidence. |
| Distribution | `0.2.3` is published on PyPI and TestPyPI, validated through clean installations from both indexes, and recorded as GitHub Release `v0.2.3` from annotated tag `4aed7df9d16907804f8c2460c004a4dc685904bc`. Its exact wheels passed expected-repository provenance verification; see [Release Evidence 0.2.3](RELEASE_EVIDENCE_0.2.3.md). Annotated `v0.2.0` remains immutable unpublished audit evidence at `7232fe3a23d92f50a693903c0a6b7cb92d0a1426`; it was never published and has no GitHub Release. | Publication, tagging, release creation, and observed package-provenance verification remain owner-controlled for every future version. |
| Mutation diagnostic | Twelve-module Linux mutmut run with a ≥95% quality gate, exact survivor-identifier parity, exact normalized-diff parity, zero untriaged records, and zero `needs_regression` classifications. | Mutation testing remains a bounded diagnostic; it does not prove that the package or a deployed agent is secure. |
| Assurance traceability | Versioned compatibility, golden-evidence, and threat-control-test contracts are check-only by default and verified by the repository reality gate. | Synthetic fixtures and source-to-test links do not establish external review, live coverage, or runtime security. |
| Resource and provenance controls | Local file/structure/chain/SARIF bounds fail closed; clean wheel/source-distribution checks and TestPyPI-first attestation workflow controls are verified. The exact `0.2.3` TestPyPI and PyPI wheels passed expected-repository verification. | The observed provenance claim applies only to the exact verified `0.2.3` files, not to a future release, local build, or deployed system. |

## Mutation acceptance control

The twelve-module mutation diagnostic is no longer the stated 9.8 blocker when the exact reviewed SHA satisfies the gate. The control requires a fresh run with the checked-in scope, a score of at least **95%**, exact survivor-identifier parity, exact normalized-diff parity, non-empty equivalence rationales, zero untriaged records, and zero `needs_regression` classifications. Any newly observed potentially reachable mutation must receive a public behavioral regression rather than a convenience reclassification.

| Required evidence | Completion condition |
|---|---|
| Survivor classification | Every surviving mutant retains an exact diff and a source-level proof of semantic equivalence; a reachable reviewer-visible difference is killed by a meaningful public regression. |
| Reproducible re-run | A fresh twelve-module mutmut run uses the checked-in `pyproject.toml` scope and records exact counts, tool version, platform limitation, selected test set, and commands. |
| Acceptance result | The measured killed score is ≥95%, identifier and diff parity both pass, and no survivor is untriaged or marked `needs_regression`. |
| Release verification | Strict local gate, package build, distribution metadata validation, reproducibility proof, local attestation verification, and hosted checks pass on the same PR head. |

## Compatibility and documentation discipline

A required-field or semantic output change receives a new versioned artifact contract. Current generation emits `trustweave.dev/bundle/v1alpha2`, `trustweave.dev/bundle-diff/v1alpha3`, and `trustweave.dev/risk-review/v1alpha2`. Historical schema resources remain packaged rather than being redefined. The repository reality check verifies source/package schema synchronization, producer-linked current artifact schemas, real-output conformance, and current documentation markers.

## External evidence that repository work cannot create

| Missing external proof | Responsible path | Do not fabricate |
|---|---|---|
| Independent reviewer feedback | Invite review of synthetic examples and record resolved, non-sensitive feedback. | Testimonials, stars, users, or adoption metrics. |
| Authenticated provenance for a future release | Publish an owner-authorized TestPyPI candidate with configured PyPI project attestations, then record exact-file `pypi-attestations` expected-repository verification before production promotion. The `0.2.3` exact-file record is preserved in [Release Evidence 0.2.3](RELEASE_EVIDENCE_0.2.3.md). | “Signed,” “verified,” or “tamper-proof” labels based on workflow configuration or local hashes alone. |
| Production release proof for a future version | Owner-authorized TestPyPI/PyPI publication and release workflow on an approved tag. | A publication claim based on a local build or green CI. |

## Non-negotiable boundaries

TrustWeave must not execute tools, call models, connect to MCP servers, access credentials, inspect third-party systems, scan live infrastructure, upload results, auto-merge updates, or claim runtime security. A rejected scope expansion is a successful result when it preserves this contract.
