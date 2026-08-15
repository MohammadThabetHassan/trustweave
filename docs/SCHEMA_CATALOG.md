# Schema Catalog

TrustWeave publishes structural JSON Schemas for local data contracts consumed outside the typed runtime. The typed parser remains authoritative for semantic validation and rejects unknown fields by default; schemas provide portable editor and CI feedback. Source and packaged schema resources are byte-synchronized and checked against real generated artifacts.

| Contract | Current schema file | Runtime version | Historical resource |
|---|---|---|---|
| Agent manifest | [`agent-manifest.schema.json`](../schemas/agent-manifest.schema.json) | `trustweave.dev/v1alpha1` | — |
| Policy | [`policy-v1alpha2.schema.json`](../schemas/policy-v1alpha2.schema.json) | `trustweave.dev/policy/v1alpha2` | [`policy.schema.json`](../schemas/policy.schema.json) for legacy v1alpha1 input. |
| Local trace | [`trace.schema.json`](../schemas/trace.schema.json) | `trustweave.dev/trace/v1alpha1` | — |
| MCP profile | [`mcp-profile.schema.json`](../schemas/mcp-profile.schema.json) | `trustweave.dev/mcp-profile/v1alpha1` | — |
| Agent Security Bundle | [`agent-security-bundle-v1alpha2.schema.json`](../schemas/agent-security-bundle-v1alpha2.schema.json) | `trustweave.dev/bundle/v1alpha2` | [`agent-security-bundle-v1alpha1.schema.json`](../schemas/agent-security-bundle-v1alpha1.schema.json) remains a bounded reader contract. |
| Bundle diff | [`bundle-diff-v1alpha2.schema.json`](../schemas/bundle-diff-v1alpha2.schema.json) | `trustweave.dev/bundle-diff/v1alpha2` | [`bundle-diff-v1alpha1.schema.json`](../schemas/bundle-diff-v1alpha1.schema.json) remains readable by compatible consumers. |
| Risk review | [`risk-review-v1alpha2.schema.json`](../schemas/risk-review-v1alpha2.schema.json) | `trustweave.dev/risk-review/v1alpha2` | [`risk-review.schema.json`](../schemas/risk-review.schema.json) preserves the historical v1alpha1 contract. |
| Risk baseline | [`risk-baseline-v1alpha2.schema.json`](../schemas/risk-baseline-v1alpha2.schema.json) | `trustweave.dev/risk-baseline/v1alpha2` | [`risk-baseline.schema.json`](../schemas/risk-baseline.schema.json) is historical and requires explicit migration. |
| Risk suppressions | [`risk-suppressions-v1alpha2.schema.json`](../schemas/risk-suppressions-v1alpha2.schema.json) | `trustweave.dev/risk-suppressions/v1alpha2` | [`risk-suppressions.schema.json`](../schemas/risk-suppressions.schema.json) is historical and requires explicit migration. |
| Other generated artifacts | [`schemas/`](../schemas/) | Versioned local contracts | Policy review, synthetic results, chain review, trace review, MCP review/inventory/scaffold, framework inventory, unsigned statements, CI summary, findings, and attestations have exact published schemas. |

Schemas are local static contracts only. They do not discover a deployed architecture, authenticate a policy source, enforce runtime controls, or establish that an agent is secure.
