# TrustWeave Governance

## Purpose

TrustWeave is maintained as a local-first, non-executing AI-agent trust-boundary review project. Governance exists to protect that contract, keep security claims evidence-based, and make decisions auditable as the contributor base grows.

## Maintainer authority

Until a broader maintainer group is published, the repository owner is the release manager and final decision-maker for releases, security-sensitive changes, schema versions, and external integrations. Contributors may propose changes through the documented contribution workflow; no merge, release, public-repository change, package publication, or signing integration is implied by a contribution.

| Decision area | Required review focus |
|---|---|
| Safety boundary | Confirm that the change adds no hidden execution, network connection, credential access, model call, or live target interaction. |
| Schema or artifact contract | Confirm strict validation, backward-compatibility behavior, tests, documentation, and a migration note if a break is unavoidable. |
| Policy or review signal | Confirm deterministic semantics, synthetic fixtures, a clear limit, and no claim of runtime enforcement. |
| Release or distribution | Confirm the release checklist, hosted CI on the exact tag target, package metadata, SBOM evidence, and explicit owner approval. |
| External integration | Confirm opt-in scope, least privilege, privacy impact, and whether the local-first core remains independent of the integration. |

## Review cadence

The maintainers should review `docs/THREAT_MODEL.md`, `docs/QUALITY.md`, and this governance policy before each minor release and at least once every 90 days while active development continues. The review should record the source revision, changed assumptions, unresolved risks, and whether any existing claims need to be narrowed.

Security-sensitive findings and proposed exceptions to the non-executing boundary require explicit repository-owner approval. A change that cannot be reviewed safely should remain out of scope rather than being merged behind an undocumented flag.

## Community path

When the repository is made public, maintainers should publish issue templates, label a small set of bounded documentation or scenario contributions as `good first issue`, and name at least two active maintainers before relying on a shared response rotation. Until then, the repository remains private and this document does not claim external community governance, OpenSSF certification, fiscal sponsorship, or a public contributor program.

## Amendments

Changes to this file require a pull request or documented direct-main review note that explains the governance impact. The changelog should mention any material change to release authority, safety scope, review cadence, or disclosure policy.
