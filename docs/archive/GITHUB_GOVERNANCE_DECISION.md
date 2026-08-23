# GitHub Governance Decision Record

## Purpose

This record helps the repository owner choose and verify a GitHub governance profile for TrustWeave. It is a **decision and evidence template**, not proof that any listed setting is currently enabled. GitHub settings remain owner-controlled.

> Do not claim a branch-protection rule, review requirement, administrator enforcement, linear-history policy, signed-commit rule, secret-scanning configuration, or trusted-publishing binding until the owner has observed the live configuration and recorded it below.

## Current observed baseline

**Observation date:** 2026-08-22  
**Observed default-branch commit:** `97df6370eab29060d1606cda0710f05a87724562`

| Control | Observed state | Interpretation |
|---|---|---|
| Force pushes to `main` | Blocked | A live protection is observed. |
| Branch deletion for `main` | Blocked | A live protection is observed. |
| Required status checks | `Quality and tests`; strict/up-to-date requirement enabled | A limited live check requirement is observed. |
| Pull-request reviews | Not required | Do not claim mandatory review. |
| Administrator enforcement | Disabled | Do not claim that administrators are bound by branch rules. |
| Linear history | Disabled | Do not claim linear-history enforcement. |

The repository’s currently observed pull-request workflow also produces the following successful check families on the reviewed heads: `Quality and tests`, Python compatibility, CodeQL analysis, dependency review, dependency audit, composite-action smoke test, and mutation quality. A check should be required only after the owner confirms it is stable, relevant, and supportable for the chosen contributor model.

## Choose one maintenance profile

Select exactly one profile before changing GitHub settings. A profile is appropriate only if it matches how the owner actually intends to maintain the repository.

| Profile | Intended model | Recommended live settings | What may be claimed after owner verification |
|---|---|---|---|
| **A. Owner-directed maintenance** | The owner may perform limited direct-main maintenance; external code changes normally use review. | Keep force-push/deletion blocks; keep strict up-to-date checks; require a deliberately chosen core check set for pull requests; document any owner exception; do not require settings that the owner will routinely bypass. | Only the exact protection/check settings the owner records. Direct-main exceptions must remain explicit. |
| **B. Review-required public maintenance** | Every code change, including owner changes, is reviewed through pull requests. | Keep force-push/deletion blocks; require pull requests; require the selected core check set; require review/conversation resolution; enable administrator enforcement and linear history only after confirming they fit the workflow. | The verified review and enforcement requirements, without implying an external audit or certification. |

### Candidate check set for owner selection

| Check family | Current observed name or family | Why it is relevant | Select for profile A | Select for profile B |
|---|---|---|---|---|
| Core quality | `Quality and tests` | Runs the repository’s principal quality and test suite. | `[ ]` | `[ ]` |
| Compatibility | `Python compatibility (3.11)` and `Python compatibility (3.13)` | Protects declared supported Python versions. | `[ ]` | `[ ]` |
| Source analysis | `CodeQL` | Provides hosted code-scanning results. | `[ ]` | `[ ]` |
| Dependency changes | `Review pull-request dependency changes` and `Audit declared runtime dependencies` | Reviews dependency diffs and declared dependency vulnerabilities. | `[ ]` | `[ ]` |
| Action safety | `Composite action smoke test` and action analysis | Verifies checked-in GitHub Action behavior and action-focused analysis. | `[ ]` | `[ ]` |
| Mutation quality | `Mutation quality and survivor gate` | Guards the maintained high-risk mutation contract. | `[ ]` | `[ ]` |

## Owner verification record

Complete this section only after reviewing the GitHub branch-protection/ruleset screen and, where available, the actual API response.

```text
Decision date (UTC):
Repository owner / release authority:
Selected profile: A | B
Settings page or ruleset URL:
Observed default branch:
Observed required status checks:
Require branch up to date: yes | no
Require pull-request reviews: yes | no
Required approval count (if applicable):
Require review from code owners: yes | no | not configured
Require conversation resolution: yes | no
Apply rules to administrators: yes | no
Require linear history: yes | no
Allow force pushes: yes | no
Allow branch deletion: yes | no
Signed-commit requirement: yes | no | not configured
Secret scanning / push protection observation:
Actions permission observation:
Trusted-publishing observation (if release-related):
Owner exceptions and rationale:
Residual gaps and next review date:
```

## Reconciliation procedure

After the owner changes a setting, verify the live state before editing public policy text. Update [Governance](../../GOVERNANCE.md), [Maintainer Handoff](MAINTAINER_HANDOFF.md), and any automation contract only when the verified record supports the wording. Preserve prior records rather than silently rewriting history.

If the owner elects profile A, the repository must not describe itself as requiring reviews for every change. If the owner elects profile B, a direct-main exception must be removed or narrowly documented. Neither profile proves code correctness, runtime enforcement, external assessment, or security efficacy.

## When to review again

Review this record before a minor release, at least every 90 days while active maintenance continues, after material workflow changes, after a change in maintainer roles, and after any incident involving branch protection, release authorization, or a bypassed required check.
