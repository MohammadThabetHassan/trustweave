# Schema Catalog

TrustWeave packages its public JSON Schemas with the Python distribution. Schema discovery uses package resources rather than a source checkout, so a wheel-installed command lists the same versioned schema catalog as a repository checkout.

```bash
trustweave schema list
trustweave schema show agent-security-bundle-v1alpha2.schema.json
```

## Current generated artifacts

| Family | Current schema version | Local purpose |
|---|---|---|
| Agent Security Bundle | `trustweave.dev/bundle/v1alpha2` | Captures a validated manifest, complete normalized policy, flow decisions, summary, limits, and provenance metadata. |
| Bundle diff | `trustweave.dev/bundle-diff/v1alpha2` | Compares supported v1alpha1/v1alpha2 bundle inputs and records both input versions. |
| Risk review | `trustweave.dev/risk-review/v1alpha2` | Records canonical local findings, explicit future/expired/escalated decision states, mismatch metadata, and limits. |
| Risk baseline and suppressions | `trustweave.dev/risk-baseline/v1alpha2` and `trustweave.dev/risk-suppressions/v1alpha2` | Binds an expiry-limited decision to the canonical fingerprint, rule ID, stable subject digest, severity, owner, and creation time. |
| Canonical finding | `trustweave.dev/finding/v1alpha1` | Defines embedded finding fields inherited by containing artifact versions. |
| Local attestation | `trustweave.dev/attestation/v1alpha3` | Records unsigned stable-payload and exact-file local integrity bindings. |
| Policy | `trustweave.dev/policy/v1alpha2` | Defines deterministic rules and bounded policy attributes. |
| Generated local reviews and inventories | Versioned `v1alpha1` contracts | Covers policy review, synthetic results, traces, MCP metadata, chain review, framework inventory, scaffolds, and unsigned statements. |

Historical `agent-security-bundle-v1alpha1.schema.json`, `bundle-diff-v1alpha1.schema.json`, and `risk-review.schema.json` remain packaged as historical contracts. They are not silently redefined. Current generation uses v1alpha2 where shown; regenerate evidence rather than relabeling older JSON.

Schema validation establishes structural conformance only. It does **not** establish authenticity, deployment status, runtime behavior, security effectiveness, or reviewer approval. The full generated catalog and migration details are available in the [repository schema documentation](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/SCHEMA_CATALOG.md) and [schema compatibility guide](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/SCHEMA_AND_COMPATIBILITY.md).
