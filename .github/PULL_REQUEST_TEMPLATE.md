# TrustWeave change summary

## What changed?

Describe the user-visible behavior, artifact contract, documentation, or maintenance change in plain language. Link an issue, audit record, or decision record when one exists.

## Why is this safe and useful?

Explain how the change improves reviewable local evidence while preserving the non-executing TrustWeave core. State any new limits, compatibility impact, reviewer decision, or intentionally deferred work explicitly.

## Exact review target

```text
Reviewed head SHA: <paste git rev-parse HEAD>
Base branch and SHA: <for example, main at 012345...>
```

All local evidence and hosted checks cited below must refer to this exact head SHA. A later push requires the evidence section and reviewer decision to be refreshed.

## Evidence supplied by the author

- [ ] I ran the local quality commands in [`docs/QUALITY.md`](../docs/QUALITY.md).
- [ ] I ran the relevant reference workflow or added a deterministic test.
- [ ] I checked the hosted workflow status for this exact head SHA.
- [ ] I did not commit generated artifacts, credentials, personal data, third-party targets, or real trace content.
- [ ] If this change touches trace review, reports omit message content and tool arguments.

## Contract and documentation impact

- [ ] Input/output schema changes have validation, compatibility evidence, and a documented migration or safe default.
- [ ] CLI options, exit codes, examples, and safety limits match implementation.
- [ ] `CHANGELOG.md`, relevant guides, the threat model, and generated records are updated when behavior changes.
- [ ] The change preserves the distinction between local consistency evidence and provenance, identity, runtime enforcement, or certification claims.

## Release-sensitive or governance impact

Check every applicable item and describe the result below.

- [ ] This change touches `.github/`, package metadata, `Dockerfile`, release material, attestations, provenance wording, source contracts, schemas, policies, or mutation/golden evidence.
- [ ] I identified the corresponding maintainer decision and exact evidence required by [`docs/MAINTAINER_HANDOFF.md`](../docs/archive/MAINTAINER_HANDOFF.md).
- [ ] This pull request does **not** authorize tagging, signing, publication, or a GitHub Release.

Describe the release-sensitive review or write `not applicable`:

```text
<review scope and evidence>
```

## Reviewer focus

Identify the one or two decisions a reviewer should examine most carefully.

## Maintainer review completion

Complete only during review; these boxes do not create approval automatically.

- [ ] I reviewed the exact head SHA above and the relevant contract or safety boundary.
- [ ] Required hosted checks are green on that SHA, or an explicit owner decision records why a non-required check is not applicable.
- [ ] I reviewed release-sensitive paths, generated evidence, and residual limits where applicable.
- [ ] Merge, tagging, publication, and release authorization were considered separately.

Reviewer decision and residual follow-up:

```text
approve | request changes | defer
<reviewer identity and any residual limit or follow-up>
```
