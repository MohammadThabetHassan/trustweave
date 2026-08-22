# Reviewer Feedback Template

## Use conditions

Use this template only through an **owner-approved** collection route for the exact packet version named in the invitation. Do not submit this template in a public issue. Do not include a name, email, employer, organization, customer, repository URL, production system detail, credential, secret, token, personal data, real trace, message content, tool argument, or live endpoint.

A reviewer may withdraw before the owner-declared analysis cutoff through the private contact route stated in the invitation. The project must not count an invitation, a downloaded packet, a public issue, or a partial response as a completed independent review.

## Required structured fields

| Field | Allowed values or format |
|---|---|
| Packet revision | Exact 40-character commit SHA from the invitation. |
| TrustWeave package version | Exact version evaluated. |
| Corpus version | `v1alpha1` unless the owner-approved packet identifies a later version. |
| Reviewer category | Practitioner, researcher, educator, maintainer, developer, or prefer not to say. |
| Independence declaration | Independent of authorship for this evaluated revision: yes/no. |
| Consent | I consent to the stated use of this response: yes/no. |
| T1 setup outcome | Completed, partially completed, blocked, or withdrew. |
| T2 reproducibility outcome | Matches, does not match, uncertain, or not completed. |
| T3 interpretation outcome | Correct, partly correct, incorrect, uncertain, or not completed. |
| T4 decision-support outcome for `TW-EVAL-004` | Prompt further review, confirms concern, no decision support, uncertain, or not completed. |
| T4 decision-support outcome for `TW-EVAL-005` | Prompt further review, confirms concern, no decision support, uncertain, or not completed. |
| T5 setup rating | Integer 1–5. |
| T5 artifact-clarity rating | Integer 1–5. |
| T5 boundary-clarity rating | Integer 1–5. |
| T6 boundary confirmation | No sensitive/live material used: yes/no. |
| Publication preference | Anonymous aggregate only, attributed quote permitted, or do not publish response. |

## Optional safe comment

A reviewer may provide a short, redacted comment about synthetic setup friction, output clarity, or an explicitly identified corpus case. Do not include any material prohibited in the use conditions. A missing comment must not be interpreted negatively.

## Maintainer handling note

A response may be included in an independent-review analysis only if it satisfies the protocol’s independence, consent, safety, and fixed-packet conditions. Before publication, maintainers must apply the redaction and aggregate-reporting rules in the [Reviewer Protocol](../../../docs/evaluation/REVIEWER_PROTOCOL.md). Report withdrawals, blocks, partial completions, disagreements, and negative comments honestly under the protocol’s stated analysis plan.
