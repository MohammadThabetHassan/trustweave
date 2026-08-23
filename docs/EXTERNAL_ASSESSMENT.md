# External Security-Process Assessment Record

## Purpose

TrustWeave may use a manually triggered OpenSSF Scorecard workflow to inspect repository-level development and supply-chain practices. The workflow is a **maintainer assessment aid**; it is not part of the TrustWeave CLI, does not inspect a user’s local inputs, and does not change the project’s non-executing product boundary.

> Until an owner-approved run exists and its result is retained, TrustWeave makes **no claim** of an OpenSSF Scorecard score, badge, certification, remediation status, external audit, or security efficacy.

## Manual-run boundary

The checked-in workflow is manual only. It checks out the repository without persisted credentials, runs the official Scorecard Action using a pinned revision, writes a SARIF result as a short-retention GitHub Actions artifact, and does not publish a badge, API result, code-scanning alert, release, issue, comment, or repository setting change.

An owner must approve each manual run and supply a factual reason. The run does not authorize a merge, release, publication, security claim, or configuration change. Review the resulting artifact and record the disposition before describing any finding publicly.

## Assessment record

Complete this record only after a manual workflow run has finished.

```text
Assessment date and time (UTC):
Repository and exact target SHA:
Workflow run URL:
Workflow input reason:
Scorecard Action pinned revision and documented version:
Result artifact URL or retained artifact identifier:
Result format:
Published externally by this workflow: no
Badge enabled: no
Code-scanning upload enabled: no
Observed aggregate score (if the retained result reports one):
Observed findings / checks:
Owner review disposition for each material finding:
Changes accepted for follow-up:
Findings deferred and rationale:
Conflicts, limitations, or interpretation notes:
Reviewer / release authority:
```

## Claim rules

| Evidence state | Permitted statement | Prohibited statement |
|---|---|---|
| No manual run | “TrustWeave has a manual assessment workflow prepared for owner review.” | “TrustWeave is Scorecard assessed,” any score, badge, certification, or remediation claim. |
| Completed private/retained run | “An owner-reviewed manual assessment ran on `<SHA>`; the retained record is available to authorized maintainers.” | A public score or external-security claim unless the result and scope are actually published and reviewed. |
| Public reviewed result | “The linked assessment reports `<specific observed fact>` for `<SHA>` on `<date>`.” | “The project is secure,” “certified,” “externally audited,” or claims beyond the report’s scope. |

## Retention and follow-up

The workflow artifact has a deliberately short retention period. If a result is material to a maintenance decision, preserve only the public-safe report elements needed for the owner record, with the exact SHA, workflow URL, tool revision, and interpretation. Do not attach credentials, security-sensitive logs, or unrelated repository data to an issue or release.

A finding should lead to one of three documented outcomes: a bounded remediation, a clearly justified deferral, or a correction of the assessment interpretation. Do not suppress a result merely to improve an apparent score. A later run is a new observation and must not silently replace an earlier record.

## Related controls

Use [GitHub Governance Decision Record](archive/GITHUB_GOVERNANCE_DECISION.md) for branch and ruleset decisions, [Governance](../GOVERNANCE.md) for authority boundaries, [Maintainer Handoff](archive/MAINTAINER_HANDOFF.md) for failed-check handling, and [Package Provenance](PACKAGE_PROVENANCE.md) for release-specific evidence. The official Scorecard Action documentation explains its own workflow and permissions; this repository records only the narrow local policy around its manual use.
