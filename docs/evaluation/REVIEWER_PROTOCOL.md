# TrustWeave Independent Reviewer Protocol

## Status and purpose

This protocol is **prepared, not yet executed**. It defines a repeatable, offline review exercise for evaluating the clarity and reproducibility of TrustWeave synthetic evidence artifacts. It is not a penetration test, a live-system assessment, or a request for proprietary data.

A completed review may be reported as independent-review evidence only when the reviewer did not author the evaluated TrustWeave or corpus revision, consented to the stated use of their feedback, and completed the fixed task pack without substituting real data.

## Reviewer task pack

A reviewer receives the following materials from the same versioned TrustWeave revision.

| Item | Purpose |
|---|---|
| TrustWeave version/tag and installation instructions | Pins the artifact under review. |
| `examples/evaluation-corpus/` | Provides safe, synthetic inputs and expected review categories. |
| Corpus runner command | Executes all supplied cases locally in a temporary output directory. |
| Two selected case reports | Supports a short evidence-interpretation exercise. |
| This protocol and feedback form | Keeps collection and analysis consistent. |

The fixed [Offline Reviewer Packet](../../examples/evaluation-corpus/reviewer-packet/README.md) provides the safe local task sequence, feedback template, and owner-reviewable drafts. It is prepared infrastructure, not a recruitment event or a completed review.

The default time budget is **45–60 minutes**. Reviewers may stop at any point and may report setup friction or uncertainty without providing an explanation.

## Required offline tasks

| Task | Reviewer action | Recorded evidence |
|---|---|---|
| T1: Setup | Install the documented package or use the documented local checkout, then run the corpus command. | Completed, blocked, or partially completed; exact non-sensitive blocker. |
| T2: Reproducibility | Confirm whether the corpus summary matches the documented expected case categories. | Agreement, disagreement, or uncertain; affected case IDs. |
| T3: Evidence interpretation | Read one expected-review case and one expected-clear case. Identify the declared evidence, review signal, and stated limitation. | Structured responses with optional explanation. |
| T4: Decision support | State whether the supplied artifact would prompt further human review, confirm an existing concern, or provide no decision support for that synthetic case. | One fixed-choice response per selected case. |
| T5: Clarity feedback | Rate setup instructions, output clarity, and scope-boundary clarity. | Five-point ratings and optional comments. |
| T6: Boundary check | Confirm that no credentials, production data, proprietary material, live endpoint, or real agent execution was used. | Required yes/no attestation. |

## Standard feedback form

The following fields must be collected consistently. Optional free text must be redacted before publication if it contains identifying or sensitive content.

| Field | Allowed values or format |
|---|---|
| Protocol version | Exact document version or commit. |
| Artifact/corpus version | TrustWeave tag or commit and corpus manifest version. |
| Reviewer category | Practitioner, researcher, educator, maintainer, developer, or prefer not to say. |
| Independence declaration | Independent of authorship for the evaluated revision: yes/no. |
| T1 setup outcome | Completed, partially completed, blocked, or withdrew. |
| T2 reproducibility outcome | Matches, does not match, uncertain, or not completed. |
| T3 interpretation outcome | Correct, partly correct, incorrect, uncertain, or not completed under a pre-specified scoring guide. |
| T4 decision-support outcome | Prompt further review, confirms concern, no decision support, uncertain, or not completed. |
| T5 ratings | Integer 1–5 for setup, artifact clarity, and boundary clarity. |
| T6 boundary confirmation | No sensitive/live material used: yes/no. |
| Optional comments | Redacted qualitative observation; no secrets, personal data, or proprietary information. |
| Publication preference | Anonymous aggregate only, attributed quote permitted, or do not publish response. |

## Analysis plan

The maintainers must preserve each completed response in a private, access-controlled record until the declared evidence cutoff. They must report the number invited, completed, partially completed, blocked, withdrawn, and excluded because of missing independence or consent. They must report all material setup blockers and all contradictory or negative comments using a documented triage category: fixed, accepted limitation, disputed with rationale, or deferred.

Aggregate reporting may state descriptive counts, medians, ranges, and anonymized themes. It must not claim statistical generalizability, runtime security efficacy, attack prevention, organizational productivity, or adoption from this small exploratory protocol.

## Consent and withdrawal

Before beginning, reviewers must receive a plain-language explanation of the purpose, materials, expected time, intended publication use, data-minimization rule, contact route, and withdrawal deadline. A reviewer may withdraw a response before the declared analysis cutoff. If raw anonymized responses will be archived, the consent statement must make that explicit.

## Prohibited activities

Reviewers must not run TrustWeave against a live MCP server, personal account, production agent, real customer data, proprietary repository, external network target, or exploit payload. They must not submit credentials, tokens, trace content, tool arguments, or contact data through a public issue.

## Current status

No independent reviews, ratings, pilot results, user counts, or outcome analysis have been collected under this protocol.
