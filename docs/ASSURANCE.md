# Assurance Map

## Purpose

TrustWeave is a local, deterministic evidence tool. This map identifies what the repository’s implemented controls demonstrate, where a reviewer can inspect the evidence, and which conclusions remain deliberately outside the product contract.

> **Evidence is not enforcement.** A passing repository control does not prove a deployed agent is secure, authenticate every local input, or authorize a production decision.

## Implemented assurance controls

| Assurance area | Implemented control | Reviewable evidence | What the control does not prove |
| --- | --- | --- | --- |
| Local-only boundary | Commands accept supplied local declarations and pre-recorded metadata; no command executes agents, tools, MCP servers, models, or application code. | [Product contract](PRODUCT_CONTRACT.md), [threat model](THREAT_MODEL.md), CLI tests, and local example fixtures. | Runtime behavior, live MCP-server behavior, or deployment safety. |
| Input and schema strictness | Typed parsers, packaged schemas, and contract tests reject unsupported declared fields and invalid shapes. | [Schema and compatibility policy](SCHEMA_AND_COMPATIBILITY.md), `schemas/`, schema conformance tests, and the repository reality check. | That supplied declarations are complete, authentic, or equal to a live system. |
| Deterministic review decisions | Core policy and review builders use validated local inputs and stable ordering; volatile generation time is injected only at the CLI boundary. | [Reproducibility and integrity contract](REPRODUCIBILITY.md), deterministic tests, fixed-time fixtures, and generated artifacts. | Authenticated source provenance or a runtime-security result. |
| Local evidence integrity | `trustweave attest` binds stable payloads and, when supplied, exact local artifact bytes; `trustweave verify` checks that local relationship. | [Reproducibility and integrity contract](REPRODUCIBILITY.md), attestation schemas, verifier tests, and synthetic evidence. | A signature, signer identity, transparency-log inclusion, or external package provenance. |
| Code quality | Formatting, linting, strict typing, static source scanning, property-based coverage, and a 95% branch-coverage threshold are required. | `pyproject.toml`, [quality guide](QUALITY.md), CI workflow, and test suite. | Absence of every defect or security vulnerability. |
| Mutation quality | A twelve-module hosted mutation gate checks score, survivor identity/diff parity, and triage completeness. | [Mutation testing record](MUTATION_TESTING.md), mutation workflow, survivor inventory, and hosted run evidence. | Complete semantic correctness outside the selected scope. |
| Packaging and runtime surface | CI builds distributions, validates metadata, installs wheel and source distributions in isolation, tests console/module CLI entry points, and checks packaged schemas. | CI workflow, `tests/test_module_entrypoint.py`, installed-wheel checks in `scripts/reality_check.py`, and release records. | Compatibility with every Python platform or downstream integration. |
| Compatibility and evidence corpus | Published `0.3.0` carries the versioned compatibility contract, support policy, six synthetic golden cases, threat-control-test traceability checks, and the v1alpha3 policy-aware bundle-diff contract. | `docs/contracts/`, `docs/COMPATIBILITY.md`, `docs/GOLDEN_EVIDENCE.md`, `docs/CONTROL_TRACEABILITY.md`, and their validators. | Independent review, live-system coverage, or evidence outside declared synthetic inputs. |
| Local resource and distribution assurance | Documented local input/structure/chain/SARIF ceilings fail closed; a clean helper archive-checks and installs wheel/source distributions in fresh temporary environments. | `docs/RESOURCE_BOUNDS.md`, `docs/DISTRIBUTION_ASSURANCE.md`, source boundary tests, and `scripts/verify_distribution_artifacts.py`. | A hosted-service performance promise, public registry identity, or universal reproducibility. |
| Build reproducibility | Fixed-epoch wheel builds and clean-checkout staged-CI runs compare deterministic output trees and validate local path hygiene. | [Reproducibility and integrity contract](REPRODUCIBILITY.md) and `scripts/verify_release_reproducibility.py`. | Byte reproducibility for all source distributions, all operating systems, or arbitrary local inputs. |
| Dependency and SBOM evidence | CI audits declared dependencies and generates a reproducible CycloneDX SBOM for the verified environment. | [Supply-chain evidence](SUPPLY_CHAIN.md), CI workflow, and generated workflow artifacts. | A complete inventory of a developer workstation or a vulnerability-free dependency graph. |
| Workflow supply-chain hygiene | Third-party actions are pinned to reviewed immutable commit SHAs and the reality checker rejects mutable references. | Workflow YAML, `scripts/reality_check.py`, and [supply-chain evidence](SUPPLY_CHAIN.md). | That the upstream action publisher or hosted platform is risk-free. |
| Release authorization | Separate build and OIDC publish jobs, manual dispatch, annotated tags, TestPyPI rehearsal, clean installation, and GitHub Release creation form the public package release procedure. | [Release guide](RELEASE.md), publish workflows, [Release Evidence 0.3.0](RELEASE_EVIDENCE_0.3.0.md), and PyPI/TestPyPI releases. | Automatic release approval, package provenance for any release that has not passed consumer verification, or runtime enforcement. |

## Authenticated package provenance status

The exact `0.3.0` TestPyPI and PyPI wheels passed official expected-repository verification against `https://github.com/MohammadThabetHassan/trustweave`. [Release Evidence 0.3.0](RELEASE_EVIDENCE_0.3.0.md) records the exact file URLs, hashes, provenance sources, verifier output, and clean-install results. This authenticated package-provenance claim is limited to those two exact distributions.

Existing local `trustweave attest` artifacts remain unsigned local-integrity evidence and are not package-release attestations. [ADR-0005](adr/ADR-0005-PACKAGE-RELEASE-PROVENANCE.md) and [Package Release Provenance](PACKAGE_PROVENANCE.md) define the TestPyPI-first path for future releases. The repository must not describe any future package release as signed, attested, or provenance-verified until its exact published distribution has passed consumer verification.

## Owner-controlled external settings

The following controls cannot be created truthfully by code alone. They require an owner decision, platform configuration, and observed evidence.

| External control | Responsible path | Current documentation rule |
| --- | --- | --- |
| PyPI trusted-publisher identity and environment approval | Confirm the configured owner, repository, workflow, environment, and release approval policy before publication. | Do not infer a publisher identity from a local workflow file. |
| PyPI package attestations | Rehearse in TestPyPI, verify a published distribution from a clean environment, then repeat for a new production release. | The observed `0.3.0` claim is limited to its exact verified files; do not extend it to a future release until its own consumer verification succeeds. |
| GitHub secret scanning, push protection, and Dependabot configuration | Review repository settings and maintainer approval paths. | Do not claim a setting is enabled merely because a document recommends it. |
| External badges, assessments, or certification | Use the issuer’s real public report and maintain the required process. | Do not create badges or ratings without independent evidence. |

## Review procedure

When evaluating a claim about TrustWeave, begin with the relevant row in this document. Inspect its linked source and test/workflow evidence, then read the stated residual limit. If a proposed change adds a command, schema, workflow, release claim, or threat-model statement, update the compatibility contract and control-traceability source in the same reviewed change.
