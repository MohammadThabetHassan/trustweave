# External Communication Checklist

## Purpose

Use this checklist before any owner-approved announcement about TrustWeave—such as a release note, project update, technical report, reviewer invitation, community post, conference submission, or external reproduction request. It is a maintenance aid, not an authorization to publish or contact anyone.

## Required factual basis

| Statement type | Required evidence before use | Never infer from |
|---|---|---|
| Package release | Exact tag, public package file, GitHub Release, and release-specific verification record. | Source metadata, a green build, a local wheel, or a planned version. |
| Package provenance | Exact file URL, SHA-256, expected-repository verifier output, and clean-install record for that named file. | Trusted-publishing workflow configuration or a local hash alone. |
| External security-process assessment | Owner-reviewed run record with exact target SHA, tool revision, retained/public result as applicable, and scope. | A checked-in workflow, a tool badge, or a prior result on another revision. |
| Independent review | Fixed packet identity, independence/consent conditions, completed responses, aggregate analysis, conflicts/limitations, and owner review. | Public comments, stars, forks, downloads, reviewer invitations, or prepared protocol documents. |
| Archive or DOI | Actual archive-service URL/identifier, exact artifact manifest, and human approval. | A local ZIP, checksum, checklist, or planned metadata. |
| Security efficacy | A narrowly scoped, independently reviewable method and result that supports exactly the wording used. | Synthetic corpus passing, static checks, CodeQL, Scorecard, or package provenance. |
| Community/adoption | Observable, genuine external activity with dates and scope. | Artificial social activity, maintainer-created accounts, or internal testing. |

## Pre-publication checklist

```text
[ ] Owner approves the audience, channel, sender identity, and exact wording.
[ ] Every material factual claim has a direct, inspectable evidence link or a clearly stated limit.
[ ] The source version, exact SHA, release/tag state, and evidence date are current and internally consistent.
[ ] A prepared candidate is called prepared or unreleased, not published, verified, released, or available on an index.
[ ] Synthetic evidence is labeled synthetic and local-only; it is not described as independent validation or runtime evidence.
[ ] No result is framed as a certification, audit, guarantee, attack-prevention result, or general security efficacy claim.
[ ] The text contains no credential, private contact, personal data, proprietary input, customer detail, production context, live target, or sensitive log.
[ ] The communication offers only the safe feedback/reproduction route appropriate to the audience.
[ ] The text does not promise response time, merge, release, compensation, publication, approval, or a favorable result.
[ ] Human authors have reviewed any research-report or archival wording for accountability and citation accuracy.
```

## Safe wording patterns

| Evidence state | Safer wording | Avoid |
|---|---|---|
| Prepared corpus and protocol | “TrustWeave includes a versioned synthetic corpus and a prepared reviewer protocol.” | “TrustWeave was independently validated.” |
| Local deterministic result | “The named synthetic command produced the documented local artifact on the stated commit.” | “TrustWeave prevents attacks” or “the system is secure.” |
| Prepared release candidate | “Source metadata is prepared as an unreleased candidate pending owner-authorized publication.” | “Version X is released” or “available on PyPI.” |
| Manual assessment workflow | “A manual assessment workflow is prepared for owner review.” | “TrustWeave has a Scorecard score/certification” without a linked reviewed result. |
| Safe external reproduction | “Technical users can reproduce the checked-in synthetic corpus locally.” | “Users should test their production agent/server with TrustWeave.” |

## Owner-only actions

Only the owner may approve an external audience, change a GitHub setting, run a manually triggered external assessment, publish to an index, create a tag or GitHub Release, submit to an archive, recruit reviewers, or publish aggregate reviewer outcomes. A successful CI job, prepared document, public issue, or synthetic test result does not grant that authority.

## Related controls

Use [Safe External Reproduction Guide](SAFE_EXTERNAL_REPRODUCTION.md) for the public-safe path, [Community Feedback Policy](COMMUNITY_FEEDBACK.md) and [Issue Triage Procedure](ISSUE_TRIAGE.md) for incoming public material, [External Security-Process Assessment Record](EXTERNAL_ASSESSMENT.md) for manual assessment results, [Release Candidate Record](archive/RELEASE_CANDIDATE_0.3.1.md) for candidate wording, and the [Evaluation Status Ledger](evaluation/STATUS.md) for evidence-state reporting.
