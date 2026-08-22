# Independent-Review Result Record Template

> **Prepared template only.** Do not complete this record, report a count, or alter the evaluation status ledger until an owner-approved review has actually occurred. Store completed raw responses in an access-controlled owner location, not in this repository and not in a public issue.

## Study-level record

```text
Packet revision / manifest SHA-256:
TrustWeave package version:
Corpus version:
Protocol version:
Owner-approved invitation date range:
Analysis cutoff:
Intended reporting use:
Owner / release authority:
```

## Response eligibility record

Assign an internal non-identifying response code. Do not record unnecessary names, contact details, employer, organization, repository, or sensitive context in the analysis dataset.

| Field | Allowed value |
|---|---|
| Internal response code | Owner-generated non-identifying code. |
| Independence declaration | yes / no / not provided. |
| Consent to stated use | yes / no / withdrawn. |
| Synthetic-only boundary confirmation | yes / no / not provided. |
| Eligibility disposition | included / excluded / withdrawn / incomplete. |
| Exclusion or withdrawal reason | Fixed protocol category only; no sensitive free text. |

A response may be counted as independent-review evidence only if independence, consent, synthetic-only boundary confirmation, and fixed-packet identity are all satisfied.

## Structured outcome record

| Field | Allowed value |
|---|---|
| T1 setup outcome | completed / partially completed / blocked / withdrew. |
| T2 reproducibility outcome | matches / does not match / uncertain / not completed. |
| T3 interpretation outcome | correct / partly correct / incorrect / uncertain / not completed. |
| T4 `TW-EVAL-004` decision-support outcome | prompt further review / confirms concern / no decision support / uncertain / not completed. |
| T4 `TW-EVAL-005` decision-support outcome | prompt further review / confirms concern / no decision support / uncertain / not completed. |
| T5 setup rating | integer 1–5 / not provided. |
| T5 artifact-clarity rating | integer 1–5 / not provided. |
| T5 boundary-clarity rating | integer 1–5 / not provided. |
| Publication preference | anonymous aggregate only / attributed quote permitted / do not publish response. |
| Optional comment disposition | none / redacted safe observation / excluded sensitive observation. |

## Aggregate-reporting checklist

Before reporting results, the owner must preserve the number invited, completed, partially completed, blocked, withdrew, excluded, and included. Report material setup blockers, disagreements, contradictions, and negative observations under the protocol’s fixed triage categories: fixed, accepted limitation, disputed with rationale, or deferred.

The report may use descriptive counts, medians, ranges, and anonymized themes only when supported by the collected record. It must not claim statistical generalizability, runtime security efficacy, attack prevention, organizational productivity, user adoption, or a favorable outcome from a small exploratory review.

## Status-ledger rule

A completed owner record is necessary but not sufficient for a public evidence claim. Update `docs/evaluation/STATUS.md` only after the owner reviews the aggregate report, confirms the consent/independence conditions, records limitations and conflicts, and determines the appropriate evidence class. Preserve the prior “not yet collected” status if the review did not occur or no eligible response was collected.
