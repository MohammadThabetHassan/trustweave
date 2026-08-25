# Current evidence and release status

> **Purpose.** This page is the public starting point for the project’s current evidence claims. It separates what the repository itself records from what has been published or independently established. It does not turn local checks, synthetic scenarios, or declared metadata into a claim about deployed-agent security.

## Status at a glance

| Evidence category | Current status | What may safely be concluded |
| --- | --- | --- |
| **Prepared source candidate** | `0.3.1` is prepared in source metadata and is **not published, tagged, uploaded, or released**. | The repository contains a candidate state; it is not package-index, release, or provenance evidence for `0.3.1`. |
| **Latest published release** | `0.3.0` is the published package and GitHub Release. | Only the documented `0.3.0` exact-file release record may support claims about the public package release. |
| **Local product boundary** | TrustWeave reviews supplied local declarations, policies, saved trace metadata, MCP metadata, and generated artifacts. | It deterministically evaluates the supplied model; it does not discover, execute, connect to, or enforce a deployed agent. |
| **External validation** | Independent reviewers, pilots, benchmarks, adoption outcomes, and archival/DOI evidence are **not yet collected**. | The repository must not claim independent efficacy, adoption, certification, or production effectiveness. |

The [release process](RELEASE.md) and [release evidence 0.3.0](RELEASE_EVIDENCE_0.3.0.md) define the immutable public-release record. A green pull request or a clean local build does not authorize publication.

## Repository-controlled evidence

The following is **project-recorded repository evidence**, not an independent security assessment.

| Control | Recorded evidence | Scope and limit |
| --- | --- | --- |
| Branch coverage | The test gate enforces **95% branch coverage**; the current recorded full-suite result is **97.13%**. | This measures exercised TrustWeave code paths, not detection coverage for real deployed agents. |
| Mutation testing | The recorded Linux run killed **6,565 of 6,691** mutants (**98.12%**) across fourteen high-risk modules. | It is a measured high-risk scope, not a package-wide claim and not proof that TrustWeave is secure. |
| Deterministic scenarios | The evaluation corpus records **12/12** passing synthetic local cases. | A passing case verifies the supplied policy decision only; it does not execute an agent, tool, model, or live target. |
| Package and supply-chain controls | The repository records reproducible distribution checks, SBOM/provenance controls, and release-specific exact-file verification for `0.3.0`. | Configured controls and local build checks must not be confused with publication evidence for the unpublished `0.3.1` candidate. |
| Governance and review | The documented merge policy requires green relevant checks and a non-author approval when pull requests are used; GitHub settings remain owner-controlled and must be verified before a server-enforced control is claimed as enabled. | Policy and owner verification reduce change-control risk; they do not establish external adoption or security efficacy. |

For the mutation method, dated run, module scope, and survivor-triage limit, see the [mutation testing record](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/MUTATION_TESTING.md). For architecture and explicit non-executing boundaries, see [Architecture](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/ARCHITECTURE.md) and the [product contract](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/PRODUCT_CONTRACT.md).

## Evidence not yet established

The following questions remain open and must not be answered by implication from the repository’s internal checks.

| Missing evidence | Why it matters |
| --- | --- |
| Independent reproduction or reviewer findings | Shows whether an unfamiliar practitioner can reproduce the workflow and find it useful. |
| Real-framework completeness checks | Tests whether supplied declarations faithfully represent a real application’s tools and trust-boundary paths. |
| External MCP discovery or verified export workflow | Would reduce reliance on manually supplied MCP metadata, but requires a separately designed safety boundary. |
| Comparative benchmark or case study | Measures review time, false positives, missed issues, and findings against a fixed corpus or real change. |
| Pilot, adoption, or externally reported regression | Establishes whether TrustWeave changes outcomes for users other than its authors. |

The project’s evaluation status is intentionally authoritative: those results are [not yet collected](EVALUATION.md). Planned packets, workflow templates, internal scenarios, or future ideas do **not** establish any of the missing evidence above.

## Claim discipline

TrustWeave is best described as **a deterministic security-policy and evidence framework for declared AI-agent trust boundaries**. It can produce repeatable review artifacts about supplied local inputs. It does **not** establish the completeness of those inputs, independently discover every runtime path, prove an approval workflow is enforced, or guarantee that a deployed agent is secure.

Maintain this page whenever a release, recorded measurement, or independently collected evaluation result changes. Update the underlying dated source record first; then update the table here with a precise scope statement and link. Do not replace “not yet collected” with a claim until the underlying evidence exists.
