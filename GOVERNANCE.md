# TrustWeave Governance

## Purpose

TrustWeave is maintained as a local-first, non-executing AI-agent trust-boundary review project. Governance exists to protect that contract, keep security claims evidence-based, and make decisions auditable as the contributor base grows.

## Maintainer authority

The repository owner is currently the release manager and final decision-maker for releases, security-sensitive changes, schema versions, public disclosures, and external integrations. Contributions are welcome through the documented issue and pull-request workflow, but a contribution does not imply merge rights, release authority, signing authority, or permission to change the project’s safety boundary.

| Decision area | Required review focus |
| --- | --- |
| Safety boundary | Confirm that the change adds no hidden execution, network connection, credential access, model call, or live-target interaction. |
| Schema or artifact contract | Confirm strict validation, compatibility behavior, tests, documentation, and a migration note if a break is unavoidable. |
| Policy or review signal | Confirm deterministic semantics, synthetic fixtures, a clear limit, and no claim of runtime enforcement. |
| Release or distribution | Confirm the release checklist, hosted CI on the exact target, package metadata, SBOM evidence, changelog, and explicit maintainer authorization. |
| External integration | Confirm opt-in scope, least privilege, privacy impact, service-side effects, and whether the local-first core remains independent. |

## Review cadence

The maintainer reviews [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/QUALITY.md](docs/QUALITY.md), [SECURITY.md](SECURITY.md), and this governance policy before each minor release and at least once every 90 days while active development continues. The review should record the source revision, changed assumptions, unresolved risks, completed release evidence, and whether existing claims need to be narrowed. [Maintainer Handoff](docs/MAINTAINER_HANDOFF.md) defines the exact review-record template, owner-controlled setting checks, and failed-check response.

Security-sensitive findings and proposed exceptions to the non-executing boundary require explicit repository-owner approval. A change that cannot be reviewed safely should remain out of scope rather than being merged behind an undocumented flag.

## Branch protection and evidence-maintenance policy

The repository’s protected `main` branch is a release-critical control. The owner should periodically confirm that force pushes and branch deletion remain blocked; that the quality, static-analysis, dependency, and mutation checks actually produced by the repository are required before normal integration; and that administrator enforcement, conversation resolution, linear history, and signed-commit requirements are configured only where they match the active contributor model.

TrustWeave currently permits owner-controlled direct-main maintenance in limited circumstances. When pull requests are used, the final reviewer must confirm that relevant review conversations are resolved and that hosted checks are green on the exact proposed head. A successful check is not authorization to merge, tag, publish, or alter the safety boundary.

This policy records the intended control review only. GitHub repository settings remain owner-controlled and must be verified in GitHub after any configuration change before the project claims that a control is enabled. Before changing or describing these controls, use the [GitHub Governance Decision Record](docs/GITHUB_GOVERNANCE_DECISION.md) to select a maintenance profile and retain the owner-observed setting record.

Independent reviewer feedback, corpus observations, and future pilot evidence must be recorded using the evidence classes and status rules in [docs/evaluation/EVALUATION_CHARTER.md](docs/evaluation/EVALUATION_CHARTER.md) and [docs/evaluation/STATUS.md](docs/evaluation/STATUS.md). Public feedback is not automatically independent evidence, and planned infrastructure is not a completed study.

## Public contribution path

Public contributors can use the repository’s issue forms for bugs and bounded feature proposals, and the pull-request template for implementation changes. Suspected vulnerabilities must follow the private route in [SECURITY.md](SECURITY.md), not a public issue. Contributions should start with [CONTRIBUTING.md](CONTRIBUTING.md) and must preserve the project’s synthetic-data, local-input, and no-execution boundaries.

The project currently has a single published release authority. It does not claim a shared maintainer rotation, OpenSSF certification, fiscal sponsorship, a security-response SLA, or an external contributor program. As active maintainers join, this document will be updated to name their authority, review responsibility, and security-reporting role before relying on a shared response process.

## Amendments

Changes to this file require a pull request or a documented direct-main review note that explains the governance impact. The changelog should mention any material change to release authority, safety scope, review cadence, disclosure policy, or contributor decision path.
