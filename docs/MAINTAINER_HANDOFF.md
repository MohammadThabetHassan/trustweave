# Maintainer Handoff and Operating Record

## Purpose

TrustWeave is a **local-first, non-executing** evidence-review tool. This runbook turns the repository’s published quality, release, and safety boundaries into a repeatable maintainer procedure. It is intentionally an operating guide, not proof that a GitHub setting, package-index configuration, signing identity, or deployment exists.

The repository owner remains the release authority described in [Governance](../GOVERNANCE.md). A successful CI run, a green pull request, or a contributor commit does not itself authorize a merge, tag, package publication, signature, GitHub Release, or a broader security claim.

## Merge decision record

Before merging a pull request, the maintainer records the following facts in the pull request review or a linked issue. Each item is about the **exact head SHA** under review, not a previous run.

| Decision area | Required maintainer check | Evidence to retain |
| --- | --- | --- |
| Scope | The change preserves the non-executing, local-input boundary and does not add an undocumented runtime, network, credential, model, or live-target interaction. | PR summary, diff review, and any updated limit statement. |
| Contracts | Schema, parser, policy, finding, risk, or CLI changes have strict validation, compatibility evidence, tests, and documentation. | Linked tests, compatibility notes, and generated-schema review. |
| Quality | Required local and hosted checks completed successfully on the current head SHA. | `gh pr checks <number>` output or hosted workflow links. |
| Security-sensitive paths | Changes to `.github/`, `src/`, `schemas/`, policies, release material, or provenance wording receive owner review. | A recorded approval or maintainer review note. |
| Generated evidence | Golden evidence, mutation triage, schemas, catalogs, or snapshots changed only through their documented regeneration path and were reviewed as data. | Generator command, reviewed diff, and check-only verifier output. |
| Claim boundary | Documentation does not turn local consistency, synthetic evidence, or configured controls into a claim of runtime enforcement, identity, certification, or future-release provenance. | Documentation review against [Product Contract](PRODUCT_CONTRACT.md) and [Assurance Gap Inventory](ASSURANCE_GAP_INVENTORY.md). |

Use the following minimum review record when GitHub review fields are insufficient:

```text
Reviewed SHA: <40-character commit SHA>
Decision: approve | request changes | defer
Scope boundary checked: yes | no
Quality and security checks green on this SHA: yes | no
Release-sensitive files reviewed: yes | not applicable
Known residual limit or follow-up: <explicit text or none>
Reviewer: <maintainer identity>
```

> A green check is necessary evidence, not an automatic authorization. The reviewer owns the merge decision.

## Owner-controlled GitHub settings

The repository source can route ownership and validate workflow files, but GitHub settings are owner-controlled. Before relying on a protection as a release or merge assurance, the owner should confirm it in the repository settings and retain a dated review note.

| Setting | Recommended state | Verification method | What this repository can prove |
| --- | --- | --- | --- |
| Default-branch protection or ruleset | Block force pushes and deletion; require pull requests and the applicable quality/security checks; require code-owner review where the contribution model supports it. | Inspect the `main` ruleset/branch-protection screen and compare required contexts with current PR check names. | Only the checked-in workflows, `CODEOWNERS`, and observed PR checks. |
| Review discipline | Require an owner or designated maintainer review for release-sensitive paths. | Inspect ruleset review requirements and the PR’s recorded reviews. | Review routing only; a repository file cannot manufacture an approval. |
| Actions permissions | Use least privilege; keep trusted publishing separate from ordinary validation. | Inspect repository Actions settings and workflow `permissions` blocks. | Workflow-declared permissions and static workflow validation. |
| Secret scanning, push protection, and Dependabot | Enable the controls appropriate to the repository plan and document response ownership. | Inspect GitHub Security settings and alerts. | No configured-state claim without an owner-observed setting or alert record. |
| Trusted publishing | Bind the index publisher to the intended repository, workflow, environment, and release authorization. | Inspect the PyPI/TestPyPI trusted-publisher configuration before a release. | Future observation is required; existing `0.3.0` evidence does not transfer. |

If the owner cannot verify a setting, record it as an **owner-controlled gap** rather than claiming the control is active.

## Failed-check response

| Signal | First response | Merge/release disposition |
| --- | --- | --- |
| CI, type, schema, documentation, build, or dependency check fails | Inspect the exact failed log; reproduce locally when possible; fix the cause and rerun all affected checks. | Do not merge or release from the failed SHA. |
| CodeQL or dependency review reports a new alert | Review affected data flow, scope, and false-positive basis; fix or document a narrowly justified disposition through the project’s security process. | Do not suppress an alert merely to make a check green. |
| Mutation gate fails | Reproduce the configured mutation run; kill behavior-changing survivors with tests or classify only semantically equivalent/defensive survivors with exact diff and rationale. | Do not leave `needs_regression`, stale IDs, or untriaged survivors. |
| Reproducibility, golden-evidence, or traceability validation fails | Treat the change as a contract drift; review the source change and update the reviewed deterministic record only through its documented maintainer path. | Do not refresh a record implicitly or accept unexplained digest drift. |
| Publication workflow fails | Stop before retrying publication. Verify tag identity, target SHA, environment approval, exact artifact bytes, and index state. | Never move a tag, overwrite a file, or publish a rebuilt artifact under the same version. |

Suspected vulnerabilities remain subject to [SECURITY.md](../SECURITY.md), not public issue triage.

## Recurring assurance review

At least every 90 days while the project is actively maintained, and before each minor release, the owner reviews [Governance](../GOVERNANCE.md), [Threat Model](THREAT_MODEL.md), [Quality](QUALITY.md), [Security](../SECURITY.md), [Compatibility](COMPATIBILITY.md), [Assurance Gap Inventory](ASSURANCE_GAP_INVENTORY.md), the [Evaluation Status Ledger](evaluation/STATUS.md), [Synthetic Corpus Lifecycle](evaluation/CORPUS_LIFECYCLE.md), [Community Feedback Policy](COMMUNITY_FEEDBACK.md), and [Public Issue Triage Procedure](ISSUE_TRIAGE.md). The review record must state the date, reviewed SHA, changed assumptions, outstanding owner-controlled settings, completed evidence, evaluation-corpus/feedback status, and whether any public claim must be narrowed.

```text
Assurance review date: YYYY-MM-DD
Reviewed SHA: <40-character commit SHA>
Reviewer / release authority: <identity>
Changed threat, dependency, release, or maintenance assumptions: <text>
Owner-controlled settings verified: <settings or explicit gaps>
Evidence reviewed: <workflow links, local commands, release record>
Evaluation corpus and feedback status: <corpus version, open safe feedback, ledger changes, or no change>
Claims narrowed or documentation updated: <text or none>
Open follow-up and owner: <text or none>
```

Keep the record in the relevant pull request, release checklist, or an issue visible to maintainers. Do not add a status badge or external-assessment claim unless an independently reviewable record supports it.

## Release boundary

Release remains a separate owner-authorized procedure. Follow [Release Procedure](RELEASE.md), the current owner checklist, [Distribution Assurance](DISTRIBUTION_ASSURANCE.md), and [Package Provenance](PACKAGE_PROVENANCE.md). The exact published `0.3.0` evidence is historical; a later release must create fresh evidence from its own annotated tag and exact artifact bytes.
