# Golden Deterministic Evidence Corpus

## Purpose

The golden evidence corpus is a curated, synthetic, local-only regression pack. It lets a reviewer regenerate representative TrustWeave evidence from a clean checkout and compare the exact artifact inventory and approved canonical digests against [`docs/golden-evidence/corpus-v1.json`](golden-evidence/corpus-v1.json).

> The corpus demonstrates deterministic handling of supplied declarations and already-recorded metadata. It does **not** execute an agent, tool, application, MCP server, model, or network request; establish a runtime-security condition; or authenticate the origin of a supplied local file.

## Reviewed cases

| Case | Evidence exercised | Expected review result | Reviewed artifacts |
| --- | --- | --- | ---: |
| `baseline-ci` | Full synthetic staged-CI evidence: scan, scenarios, policy review, chain review, SARIF, local attestation, report, and summary. | Clear local staged CI. | 10 |
| `framework-imports` | Checked-in LangGraph, OpenAI Agents, and CrewAI declaration snapshots. | Local normalization only. | 3 |
| `mcp-profile-review` | Saved `tools/list` metadata plus clear and review-required MCP profiles. | One clear and one review-required local profile result. | 5 |
| `trace-risk-lifecycle` | Minimized clear/review-required traces and current-version empty baseline/suppression lifecycle input. | One clear and one review-required trace; local risk review remains reviewable. | 6 |
| `change-review-sarif` | Declared capability growth, bundle diff, approval-boundary policy review, and local SARIF conversion. | Review-required policy artifact with local SARIF evidence. | 7 |
| `malformed-input` | A manifest containing an intentionally unsupported local field. | Exit code `2`; no artifact is published. | 0 |

All paths, digests, expected exit statuses, fixed generation time, and prohibited output markers are versioned in the corpus manifest. JSON and SARIF digests use canonical JSON; Markdown digests use exact UTF-8 bytes. The checker validates known generated JSON artifacts against their shipped structural schemas and rejects temporary paths, checkout paths, a fixture email marker, and token-like output text.

## Check-only verification

Run the default command from a repository checkout with development dependencies installed:

```bash
python scripts/verify_golden_evidence.py
```

The default mode creates a temporary case tree under the checkout, runs only TrustWeave commands over checked-in synthetic inputs, validates the generated evidence, compares it with the reviewed manifest, and removes the temporary tree. It does not alter tracked corpus data, invoke a shell through input data, connect to a service, or refresh a snapshot implicitly.

## Controlled updates

A change to an input, command, artifact path, schema, expected exit status, rendered output, or digest is a contract change. Review the full diff first, then use the explicit maintainer-only update command:

```bash
python scripts/verify_golden_evidence.py \
  --update \
  --confirm-update I_HAVE_REVIEWED_GOLDEN_EVIDENCE
```

The confirmation is intentionally exact. The command writes only the versioned corpus manifest after every case, output-safety check, schema validation, and expected-exit assertion succeeds. Commit the changed manifest in the same review as the causal source, test, or documentation change; do not use it to make output drift disappear.

## Interpretation limits

The corpus contains no credentials, private certificates, live service endpoints, message bodies, tool arguments, external target data, absolute checkout paths, or volatile timestamps. A matching corpus result proves that the reviewed local implementation still renders this limited synthetic evidence as approved. It does not prove completeness for arbitrary inputs, performance on unbounded data, package provenance, real MCP-server behavior, or runtime enforcement.
