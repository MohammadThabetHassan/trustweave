# TrustWeave change summary

## What changed?

Describe the user-visible behavior, artifact contract, or documentation change in plain language. Link an issue or decision record when one exists.

## Why is this safe and useful?

Explain how the change improves reviewable local evidence while preserving the non-executing TrustWeave core. State any new limits or reviewer decisions explicitly.

## Evidence

- [ ] I ran the local quality commands in [`docs/QUALITY.md`](../docs/QUALITY.md).
- [ ] I ran the relevant reference workflow or added a deterministic test.
- [ ] I did not commit generated artifacts, credentials, personal data, third-party targets, or real trace content.
- [ ] If this change touches trace review, reports omit message content and tool arguments.

## Contract and documentation impact

- [ ] Input/output schema changes have validation, compatibility evidence, and a documented migration or safe default.
- [ ] CLI options, exit codes, examples, and safety limits match implementation.
- [ ] `CHANGELOG.md`, relevant guides, and the threat model are updated when behavior changes.

## Reviewer focus

Identify the one or two decisions a reviewer should examine most carefully.
