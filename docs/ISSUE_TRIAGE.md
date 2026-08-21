# Public Issue Triage Procedure

## Purpose

This procedure gives maintainers a consistent, disclosure-safe way to triage public issues. It applies to bugs, feature proposals, documentation corrections, synthetic corpus proposals, and evaluation observations. It does not create a response-time guarantee, a support contract, automated moderation, automatic closure, automatic labeling, automatic merge, or permission to collect sensitive information.

> **Safety first:** suspected vulnerabilities, credentials, tokens, personal data, production artifacts, proprietary manifests, live endpoint details, message content, tool arguments, exploit payloads, and unauthorized material must not be processed through a public issue.

## Intake decision

| Incoming item | Maintainer action | Public disposition |
|---|---|---|
| Clear, safe, reproducible local defect | Confirm the reported version/commit and safe local reproduction steps; assess scope. | `needs-reproduction`, then `documentation` or a bounded implementation issue as appropriate. |
| Documentation correction | Check the asserted text against the checked-in implementation and evidence records. | `documentation` or `accepted-limitation`; retain an explicit correction rationale. |
| Bounded feature request | Check the user decision, deterministic evidence, compatibility impact, test approach, and safety boundary. | `needs-scope-review`, `deferred`, or a scoped implementation proposal. |
| Synthetic corpus proposal | Require a synthetic rationale, expected category, non-claim, local fixture design, and a clear/no-finding control where relevant. | `corpus-proposal` and a lifecycle-policy review. |
| Evaluation observation | Record corpus/protocol version and safe observation only; distinguish it from a study response. | `evaluation-feedback`, with any follow-up linked to the public record. |
| Suspected vulnerability or sensitive data | Stop public discussion; direct the reporter to the private route in `SECURITY.md`. Do not quote, copy, or request the sensitive material. | `security-private-route` only when safe to apply; otherwise use a minimal public redirection. |
| Out-of-scope or unsafe request | State the relevant local-only or disclosure boundary and close only with a short, respectful rationale. | `accepted-limitation` or `deferred`. |

## Required triage record

For a material issue, the maintainer records the issue URL, current label, local reproduction status, safety/disclosure decision, any related corpus case or documentation path, and next owner. The record can live in the issue itself when it contains only public-safe material. Do not create a second public ledger containing personal information or private security details.

A public evaluation observation is **project input**, not an independently collected reviewer-study result. It must not be counted as reviewer recruitment, usability evidence, adoption, a pilot outcome, or a benchmark result unless the owner has separately run a consent-aware study under the approved reviewer protocol.

## Corpus-proposal review

Before accepting a corpus proposal, a maintainer must apply [Synthetic Corpus Lifecycle](evaluation/CORPUS_LIFECYCLE.md). The proposed case must be local-only, deterministic, checked in, synthetic, and accompanied by a specific non-claim. It must not introduce an external URL, live host, downloaded asset, secret, personal information, customer data, production trace, tool invocation, model call, server connection, or target interaction.

If the proposal is accepted, its pull request must identify the originating public issue without converting the reporter into a study participant or attributing a security finding to them. The change needs the required local tests, full quality gate, and normal owner-controlled review.

## Review cadence and escalation

At least once every 90 days while active development continues, and before each minor release, the repository owner reviews open public issues for security routing, unresolved documentation drift, corpus proposals, evaluation feedback, and stale scope assumptions. The owner records only the count or links required for maintenance, plus any owner-controlled gaps and follow-up decisions.

There is no service-level commitment. A maintainer may defer an in-scope issue when capacity is limited, but should preserve a concise reason and never use a green workflow, a public comment, or a label as authorization to merge, release, publish, alter the safety boundary, or make a security claim.
