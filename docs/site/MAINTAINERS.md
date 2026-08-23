# Maintainer review and release boundary

TrustWeave is maintained as a **local-first, non-executing** evidence-review project. A green workflow validates the checked source revision; it does not automatically authorize a merge, package publication, signing action, GitHub Release, or a claim of runtime security.

## Reviewer path

Before a maintainer merges a pull request, the reviewer should confirm the exact head SHA, inspect the affected contract and boundary, and ensure the relevant local and hosted evidence is green on that SHA. Security-sensitive changes include source, schemas, policies, workflow files, provenance wording, and release material.

| Review question | Required decision |
| --- | --- |
| What must be checked before merge? | Record the exact reviewed SHA, scope boundary, hosted-check status, release-sensitive review, residual limit, and reviewer identity. |
| What does the project validate? | Deterministic review of supplied declarations and already-recorded local metadata, with strict schemas and documented evidence artifacts. |
| What is deliberately excluded? | Runtime interception, model calls, live connections, credentials, tool invocation, hosted operation, identity proof, external provenance, and certification. |
| What requires owner action? | Branch protection, review requirements, Actions permissions, secret-scanning settings, trusted-publisher configuration, and release authorization. |

The full versioned operating record is maintained in the repository source as `docs/archive/MAINTAINER_HANDOFF.md`. It requires an explicit human review decision; repository files and successful checks cannot manufacture an approval.

## Owner-controlled settings

Branch protection, review requirements, Actions permissions, secret scanning, package-index trusted publishing, and security-alert settings are controlled through GitHub or package-index administration. The repository documents recommended checks and required evidence, but it does not infer that an external control is active. A maintainer should verify those settings before relying on them for a merge or release decision.

## Release is separate from merge

A release requires its own annotated tag, exact artifact build, trusted-publishing authorization, package-index observation, and release evidence. Merging a pull request does not publish software. See the site-local [release process](RELEASE.md) for the release boundary and the exact published-release record.
