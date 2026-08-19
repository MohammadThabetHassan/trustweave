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

## Clean-checkout staged-CI release verification

The owner-release procedure must be directly executable from a clean checkout and must not depend on a tracked root `trustweave.toml`. Run the following command from the exact reviewed checkout; replace neither the fixed timestamp nor the source revision with a different value between the two internal executions.

```bash
python3 scripts/verify_release_reproducibility.py \
  --source-revision "$(git rev-parse HEAD)" \
  --generated-at 2026-08-19T00:00:00+00:00
```

The helper creates two temporary run directories beneath the checkout. In each, it writes an explicit temporary configuration with relative input paths to the tracked `examples/support-agent.manifest.json`, `policies/default-policy.json`, `scenarios/default-scenarios.json`, and `examples/chains/safe-sanitized-external.chain.json` files. Each temporary configuration sets `output_dir = "artifacts"`, a portable relative `sarif_output = "reports/trustweave.sarif"`, `failure_threshold = "none"`, and `reproducible = true`; it enables `scan`, `scenarios`, `policy_review`, `chain_review`, `sarif`, `attestation`, `report`, and `summary`.

| Check | Required result |
| --- | --- |
| Temporary configuration | Both generated TOML files validate and use only documented, tracked local inputs plus relative output paths. |
| Artifact comparison | Both ten-file output trees have exactly the same relative paths and byte content; a difference fails the command. |
| Temporary-path review | Every emitted artifact is rejected if it contains `.trustweave-ci-`, `.trustweave-release-repro-`, `/tmp/`, the checkout path, or a run-directory path. |
| Supplied-file attestation | Each generated v1alpha3 attestation is verified with its actual `agent-security-bundle.json` and `security-test-results.json` files. |
| Cleanup | Both temporary run directories are removed and the repository working tree must be unchanged from command start. |
| Emitted artifacts | `agent-security-bundle.json`, `attestation.json`, `chain-review.json`, `chain-review.md`, `ci-summary.json`, `policy-review.json`, `policy-review.md`, `report.md`, `reports/trustweave.sarif`, and `security-test-results.json`. |

This is evidence for deterministic staging and artifact rendering when the declared inputs, fixed provenance, and selected local stages are held constant. It does not prove reproducibility across operating systems, Python versions, different source trees, different output destinations, or separately rebuilt distributions. It also remains unsigned local evidence and does not establish provenance, identity, or runtime security.

## Golden evidence and clean-environment assurance

[`docs/golden-evidence/corpus-v1.json`](golden-evidence/corpus-v1.json) records a separately reviewed synthetic corpus for representative framework declarations, saved MCP metadata, trace/risk lifecycle review, change review, SARIF conversion, full staged CI, and malformed input. The default command is check-only:

```bash
python scripts/verify_golden_evidence.py
```

It creates a temporary case tree, runs only local TrustWeave commands against checked-in synthetic inputs, validates known generated JSON against shipped schemas, rejects temporary/check-out path leakage and selected privacy markers, and compares the exact approved artifact inventory and canonical digests. It removes the temporary tree before returning. Digest refresh requires an explicit maintainer confirmation; CI and the repository reality gate never update it automatically. See [Golden Deterministic Evidence Corpus](GOLDEN_EVIDENCE.md) for the review procedure.

The local loader, declared-chain analyzer, and SARIF exporter also enforce deterministic resource boundaries. See [Local Resource Bounds](RESOURCE_BOUNDS.md) for the file-size, structural, traversal, and result-cardinality limits and their fail-closed behavior. These bounds describe local processing only; they do not provide a hosted-runner performance guarantee or a live-system availability claim.

## Attestation migration

New attestations use `trustweave.dev/attestation/v1alpha3`. Their `chain_sha256` binds stable bundle/test-result payload digests, exact generated-file digests, subject names, and the stated source revision. Volatile `generated_at` metadata remains outside this integrity material. `trustweave verify --attestation PATH --bundle PATH --test-results PATH` checks both the actual supplied file bytes and their stable payloads against the recorded bindings.

The verifier continues to read legacy `trustweave.dev/attestation/v1alpha1` and `v1alpha2` statements using their documented internal-chain semantics. Older statements cannot establish v1alpha3 exact-file binding retroactively. Regenerate stored local evidence to receive v1alpha3 semantics; no live service, credential, signing action, or migration upload is involved.

> A successful verification proves only internal consistency of the recorded local relationship. It does not authenticate a person, sign an artifact, validate a deployment, or prove that an agent system is secure.
