# TrustWeave Community Feedback Policy

## Purpose

TrustWeave welcomes genuine feedback that improves the clarity, reproducibility, and safety of local evidence review. This policy defines the public routes for bug reports, bounded feature ideas, corpus-case proposals, and evaluation observations. It does not create a support guarantee, collect study results automatically, or authorize maintainers to process sensitive materials.

## Public routes

| Feedback type | Route | Expected content | Do not submit |
|---|---|---|---|
| Reproducible defect | Bug-report issue form | TrustWeave version, safe reproduction steps, expected and actual behavior, sanitized output. | Secrets, personal data, production traces, real tool arguments, or live targets. |
| Bounded enhancement | Feature-request issue form | User decision improved, deterministic evidence, compatibility effect, tests, and scope boundary. | A request to add hidden network, model, credential, or execution behavior. |
| Evaluation observation | Evaluation-feedback issue form | Corpus/protocol version, case ID, setup outcome, clarity observation, and suggested correction. | Identifiable study responses, proprietary workflows, or a claim that the observer represents all users. |
| Corpus proposal | Evaluation-feedback issue form | Synthetic case rationale, expected review category, no-finding control consideration, and non-claim. | Exploit payloads, production configurations, or runnable targets. |
| Security concern | Private route in `SECURITY.md` | Follow the project security-reporting instructions. | Public issue disclosure of a suspected vulnerability or sensitive reproduction. |

## Triage categories

Maintainers may label a public item as `needs-reproduction`, `needs-scope-review`, `corpus-proposal`, `evaluation-feedback`, `accepted-limitation`, `security-private-route`, `documentation`, `duplicate`, or `deferred`. Labels communicate the current review state; they do not guarantee implementation, endorsement, release approval, or a response date.

When an item informs a future corpus or paper change, maintainers must preserve its origin and distinguish it from independently collected reviewer-study evidence. Public feedback is valuable project input, but it is not automatically a participant response or an adoption metric.

## Maintainer responsibilities

Maintainers should acknowledge clear, in-scope reports when capacity allows, request safe reproductions rather than private data, and close items with a concise rationale when they are out of scope. They must route vulnerabilities privately, decline sensitive attachments, and avoid collecting personal or production data in issue comments.

The project does not promise a fixed response time. Release, merge, package publication, and security-sensitive decisions remain owner-controlled actions under the documented governance and release procedure.

## Contributor expectations

Contributors must preserve TrustWeave’s local-first, non-executing boundary. Feedback should describe a reviewer decision, safe local artifact, deterministic expected behavior, and explicit limitation. Contributors should not ask the project to run code, connect to external services, inspect a live system, handle credentials, or process a real agent trace.
