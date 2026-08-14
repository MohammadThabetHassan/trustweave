# Schema Catalog

TrustWeave packages its public JSON Schemas with the Python distribution. Schema discovery uses package resources rather than a source checkout, so a wheel-installed command can list and display the same versioned schema catalog as a repository checkout.

```bash
trustweave schema list
trustweave schema show agent-security-bundle-v1alpha1.schema.json
```

## Public schema families

| Family | Current schema version | Local purpose |
|---|---|---|
| Agent Security Bundle | `trustweave.dev/bundle/v1alpha1` | Captures a validated manifest, normalized policy, flow decisions, summary, limits, and provenance metadata. |
| Canonical finding | `trustweave.dev/finding/v1alpha1` | Defines embedded finding fields inherited by containing artifact versions. |
| Local attestation | `trustweave.dev/attestation/v1alpha3` | Records unsigned stable-payload and exact-file local integrity bindings. |
| Policy | `trustweave.dev/policy/v1alpha2` | Defines deterministic rules and optional bounded policy attributes. |
| Chain manifest | `trustweave.dev/chain-manifest/v1alpha1` | Defines a reviewer-supplied trust-boundary graph for bounded static propagation. |
| Risk review | `trustweave.dev/risk-review/v1alpha1` | Records canonical local findings, deterministic risk states, expiry decisions, and limits. |

Schema validation establishes that a supplied document conforms to its declared structural contract. It does **not** establish authenticity, deployment status, runtime behavior, security effectiveness, or reviewer approval.

The full generated catalog and compatibility notes are available in the [repository schema documentation](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/SCHEMA_CATALOG.md) and [schema compatibility guide](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/SCHEMA_AND_COMPATIBILITY.md).
