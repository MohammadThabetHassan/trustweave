# Reproducibility and Integrity Contract

## Purpose

TrustWeave makes **deterministic decisions** about declared and pre-recorded local evidence. This document distinguishes that guarantee from byte reproducibility, generation provenance, and local file integrity so that a timestamp is never mistaken for a policy input or runtime-security claim.

## Guarantees

| Property | TrustWeave guarantee | Explicit limit |
| --- | --- | --- |
| Deterministic decisions | The same validated manifest, policy, scenario, trace metadata, or profile metadata produces the same ordered local decision and finding content. | The decision concerns only supplied local evidence; it does not establish runtime behavior or enforcement. |
| Stable evidence payload | Core builders are pure. They do not read a clock or environment; optional `generated_at` provenance is injected at the application boundary. | Stable payload equality does not prove the input artifacts are authentic. |
| Reproducible artifact bytes | Supplying the same inputs, output paths, source revision, and `--generated-at` value produces byte-identical JSON artifacts. | Different output paths can change an attestation subject name, even when the stable evidence payload is identical. |
| Fixed-epoch CLI output | When `--generated-at` is omitted, `SOURCE_DATE_EPOCH` supplies the UTC generation time. | An unset epoch intentionally falls back to current UTC for ordinary local use. |
| Local integrity evidence | Attestation integrity chains cover canonical stable evidence payloads after excluding `generated_at`. The statement also records exact generated-file hashes. | The attestation is unsigned, has no identity binding or transparency-log record, and does not establish provenance or runtime security. |

## Timestamp resolution

Artifact-producing commands resolve generation metadata in this order:

1. The global `--generated-at` option, using an ISO 8601 value with a UTC offset.
2. `SOURCE_DATE_EPOCH`, using a non-negative Unix timestamp.
3. The current UTC clock at the CLI boundary.

For example, the following produces fixed-time local evidence without contacting any service:

```bash
trustweave --generated-at 2026-08-13T00:00:00+00:00 scan \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --output-dir artifacts

SOURCE_DATE_EPOCH=0 trustweave test \
  --policy policies/default-policy.json \
  --scenarios scenarios/default-scenarios.json \
  --output-dir artifacts
```

## Recorded staged-CI verification

On 2026-08-14, the complete configured local CI workflow was run twice with the same declared local inputs, source revision `fixed-revision`, `reproducible = true`, and `--generated-at 2026-08-14T00:00:00+00:00`. Each run used scan, scenarios, policy review, chain review, SARIF, attestation, report, and summary stages. The two output trees were copied after each run and compared with `diff -qr`; all **10** emitted files were byte-identical.

| Check | Result |
| --- | --- |
| Artifact comparison | `diff -qr /tmp/repro-first /tmp/repro-second` completed with no differences. |
| Temporary-path review | A recursive search of the second output found no `.trustweave-ci-`, `/tmp/`, or `/home/ubuntu/` strings. |
| Emitted artifacts | `agent-security-bundle.json`, `attestation.json`, `chain-review.json`, `chain-review.md`, `ci-summary.json`, `policy-review.json`, `policy-review.md`, `report.md`, `security-test-results.json`, and `trustweave.sarif`. |

This is evidence for deterministic staging and artifact rendering when inputs and the configured destination are held fixed. It does not prove reproducibility across operating systems, Python versions, different source trees, different output destinations, or separately rebuilt distributions. It also remains unsigned local evidence and does not establish provenance, identity, or runtime security.

## Attestation migration

New attestations use `trustweave.dev/attestation/v1alpha3`. Their `chain_sha256` binds stable bundle/test-result payload digests, exact generated-file digests, subject names, and the stated source revision. Volatile `generated_at` metadata remains outside this integrity material. `trustweave verify --attestation PATH --bundle PATH --test-results PATH` checks both the actual supplied file bytes and their stable payloads against the recorded bindings.

The verifier continues to read legacy `trustweave.dev/attestation/v1alpha1` and `v1alpha2` statements using their documented internal-chain semantics. Older statements cannot establish v1alpha3 exact-file binding retroactively. Regenerate stored local evidence to receive v1alpha3 semantics; no live service, credential, signing action, or migration upload is involved.

> A successful verification proves only internal consistency of the recorded local relationship. It does not authenticate a person, sign an artifact, validate a deployment, or prove that an agent system is secure.
