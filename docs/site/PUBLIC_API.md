# Public API and evidence exports

Downstream Python callers should import from `trustweave.api`. The public surface is typed and data-only; callers supply already-loaded local structures and any explicit provenance timestamp. The package includes a `py.typed` marker in its wheel.

| Public service | Local deterministic purpose |
| --- | --- |
| `parse_manifest`, `parse_policy` | Validate supplied declarations into immutable typed models |
| `evaluate_flow`, `evaluate_manifest`, `build_bundle` | Evaluate ordered policy decisions for declared paths |
| `review_policy`, `review_declared_chains`, `diff_bundles` | Produce review evidence from local declarations and artifacts |
| `normalize_findings`, `review_risks` | Normalize compatible findings and apply visible expiry-bound reviewer decisions |
| `LocalReviewResult` | Typed envelope for an already-generated local review artifact |
| `ValidationError`, `InputOutputError` | Expected failures for invalid data and safe local I/O boundaries |

```python
from trustweave.api import build_bundle, parse_manifest, parse_policy

manifest = parse_manifest(local_manifest)
policy = parse_policy(local_policy)
bundle = build_bundle(manifest, policy, generated_at="2026-08-14T00:00:00+00:00")
```

The API does not read files, inspect environment secrets, connect to a network, discover or load plugins, execute an agent, model, or tool, or access a clock without an explicit input. Its output is design-time evidence only; it does not enforce a runtime decision or establish deployed-system security.

## SARIF and attestations

The command-line interface can export selected local review artifacts to deterministic SARIF 2.1.0 evidence and can build or verify hash-linked attestation statements. SARIF export never uploads an artifact. Attestation verification detects mismatches in the supplied files and statement chain but does not authenticate an unsigned artifact or prove its origin.

```shell
trustweave sarif --policy-review artifacts/policy-review.json --output artifacts/trustweave.sarif
trustweave attest --bundle artifacts/agent-security-bundle.json \
  --test-results artifacts/security-test-results.json --source-revision local-review
```
