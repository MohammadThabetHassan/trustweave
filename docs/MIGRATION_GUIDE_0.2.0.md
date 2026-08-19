# TrustWeave 0.1.1 to 0.2.1 Migration Guide

> **Scope:** This guide explains local document and configuration migration. It does not authorize a merge, tag, signature, package upload, GitHub Release, or production deployment.

## Migration overview

TrustWeave 0.2.1 retains the local, declarative review boundary of 0.1.1 while carrying forward the 0.2 hardening for artifact validation and risk lifecycle handling. Migrate copies of local inputs in a branch or scratch directory first, run the validation commands below, and retain original 0.1.1 evidence unchanged as historical input until the local migration review is complete. The prior `v0.2.0` tag remains an immutable unpublished audit record and is not an installable public release; install published [`trustweave==0.2.1`](https://pypi.org/project/trustweave/0.2.1/) instead.

| Surface | Required change | Validation command |
| --- | --- | --- |
| CI configuration | Rename `baseline` to `baseline_bundle` and `candidate` to `candidate_bundle`. | `trustweave config validate --config trustweave.toml` |
| Bundle evidence | Retain only authentic semantically valid v1alpha1 documents; regenerate or migrate current evidence to v1alpha2. | `trustweave verify --attestation attestation.json --bundle bundle.json --test-results security-test-results.json` |
| Risk review inputs | Use strict v1alpha2 baseline and suppression documents with canonical v3 fingerprints. | `trustweave baseline validate --input baseline.json` and `trustweave suppressions validate --input suppressions.json` |
| CI stage selection | Use only the fourteen documented stage names and satisfy configured stage dependencies. | `trustweave ci --config trustweave.toml --quiet` |
| Reproducible CI | Provide `--generated-at` or `SOURCE_DATE_EPOCH` when `reproducible = true`. | `trustweave --generated-at 2026-08-18T00:00:00+00:00 ci --config trustweave.toml --quiet` |

## 1. Update configuration field names

Replace the old comparison-input keys with the explicit current names. Do not retain both names: configuration is strict and rejects unsupported fields.

```toml
[tool.trustweave]
baseline_bundle = "artifacts/baseline/agent-security-bundle.json"
candidate_bundle = "artifacts/candidate/agent-security-bundle.json"
```

The complete supported stage list is `validate`, `scan`, `scenarios`, `policy_review`, `policy_coverage`, `diff`, `trace_review`, `mcp_profile_review`, `chain_review`, `risk`, `sarif`, `attestation`, `report`, and `summary`. A selected stage remains local-only and must satisfy its documented input prerequisites.

```bash
trustweave config validate --config trustweave.toml
trustweave config show --config trustweave.toml
```

## 2. Migrate bundle evidence

### Historical v1alpha1 bundles

A historical bundle with `schema_version` matching the v1alpha1 contract is no longer accepted merely because it resembles a JSON bundle. 0.2.0 validates its historical manifest, policy, findings, summary, and limits according to the authentic v0.1.1 shape. Preserve an original valid historical file when it is needed for comparison, but do not edit it to imitate a newer contract.

If validation fails, use the original 0.1.1 source inputs to regenerate the historical artifact or generate a current v1alpha2 bundle from current manifest and policy inputs. Do not manually patch hashes, findings, summaries, or generated timestamps in an attempt to make evidence appear valid.

### Current v1alpha2 bundles

Current evidence should use `trustweave.dev/bundle/v1alpha2`. Generate it from a strict manifest and policy rather than hand-authoring a bundle:

```bash
trustweave scan \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --output artifacts/agent-security-bundle.json
```

Then use the output with a matching synthetic test result when creating or verifying an attestation.

## 3. Migrate risk-review, baseline, and suppression documents

0.2.0 uses strict v1alpha2 reviewer-decision documents. Their identities are canonical risk fingerprints in the `trustweave/fingerprint/v3` namespace, not ad hoc titles, messages, file paths, or older fingerprint versions.

| Document | Required invariant |
| --- | --- |
| Risk review | Input findings must normalize to valid, deterministic canonical fingerprints and local provenance. |
| Baseline | Each entry has one canonical fingerprint, reviewer reason, valid creation/expiry timestamps, and an expiry strictly later than the supplied review timestamp. |
| Suppression | Each entry has one canonical fingerprint, scoped reviewer reasoning, valid timestamps, and explicit expiry behavior. |
| Lifecycle | A decision whose `expires_at` equals `reviewed_at` is expired, not active. Duplicate fingerprints are rejected. |

Use validation before a review run:

```bash
trustweave baseline validate --input artifacts/risk-baseline.json
trustweave suppressions validate --input artifacts/risk-suppressions.json
trustweave risk-check \
  --input artifacts/policy-review.json \
  --baseline artifacts/risk-baseline.json \
  --suppressions artifacts/risk-suppressions.json \
  --output artifacts/risk-review.json
```

Do not convert an old fingerprint by copying a string into a new document. Re-run the local normalization or baseline-creation workflow against the source review artifacts, then record a new reviewer decision for the resulting canonical identity.

## 4. Validate staged CI migration

Use a fixed timestamp when testing a reproducible configuration, and publish only to a scratch output directory until migration review is complete.

```bash
trustweave --generated-at 2026-08-18T00:00:00+00:00 \
  ci --config trustweave.toml --source-revision migration-check --quiet
```

Inspect the generated `ci-summary.json`, expected selected artifacts, and the v1alpha3 `attestation.json`. The coordinator stages output before publication; a semantic failure must not replace an existing artifact directory with a partial result.

## 5. Rollback and evidence preservation

If a migrated configuration or document fails validation, restore the previous tracked input file rather than editing generated artifacts in place. Keep the 0.1.1 evidence as historical reference and regenerate current artifacts from declarations. Because `v0.2.0` was never published, there is no package yank or release rollback to perform; the corrected public release is [`0.2.1`](https://pypi.org/project/trustweave/0.2.1/).

If an issue is discovered in published 0.2.1, follow the owner checklist’s release-specific rollback procedure: stop further publication, document the affected version, remove or yank only through the authorized registry controls, and publish a verified corrective release only after validation. Do not rewrite tags, force-push shared branches, delete evidence, or silently alter previously published artifacts.

## Migration completion criteria

A migration is ready for owner review only when strict configuration and decision validators pass, local CI produces the expected staged artifacts, attestation verification passes for the exact supplied files, and all required repository checks are green. The separate release-acceptance gate also requires zero unresolved mutation triage classifications and exact hosted survivor-triage parity; see [RELEASE_NOTES_0.2.1.md](RELEASE_NOTES_0.2.1.md).
