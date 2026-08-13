# Schema Catalog

TrustWeave publishes structural JSON Schemas for local data contracts that are consumed outside the typed runtime. The typed parser remains authoritative for semantic validation and rejects unknown fields by default; schemas provide portable editor and CI feedback.

| Contract | Schema file | Runtime version |
|---|---|---|
| Legacy agent manifest | [`agent-manifest.schema.json`](../schemas/agent-manifest.schema.json) | `trustweave.dev/v1alpha1` |
| Legacy policy | [`policy.schema.json`](../schemas/policy.schema.json) | `trustweave.dev/v1alpha1` |
| Policy V2 | [`policy-v1alpha2.schema.json`](../schemas/policy-v1alpha2.schema.json) | `trustweave.dev/policy/v1alpha2` |
| Local trace | [`trace.schema.json`](../schemas/trace.schema.json) | `trustweave.dev/trace/v1alpha1` |
| MCP profile | [`mcp-profile.schema.json`](../schemas/mcp-profile.schema.json) | `trustweave.dev/mcp-profile/v1alpha1` |
| Risk review | [`risk-review.schema.json`](../schemas/risk-review.schema.json) | `trustweave.dev/risk-review/v1alpha1` |
| Risk baseline | [`risk-baseline.schema.json`](../schemas/risk-baseline.schema.json) | `trustweave.dev/risk-baseline/v1alpha1` |
| Risk suppressions | [`risk-suppressions.schema.json`](../schemas/risk-suppressions.schema.json) | `trustweave.dev/risk-suppressions/v1alpha1` |

Schemas are local static contracts only. They do not discover a deployed architecture, authenticate a policy source, enforce runtime controls, or establish that an agent is secure.
