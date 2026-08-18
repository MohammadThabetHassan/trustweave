# Schema and Compatibility

## Compatibility policy

TrustWeave treats local manifests, policies, scenarios, bundles, reviews, and attestations as **versioned evidence contracts**. Runtime validation remains dependency-free and authoritative; JSON Schema provides structural interoperability and editor feedback. Every published root schema is byte-identical to its packaged counterpart, and generated output is tested against both resources.

| Artifact | Current emitted version | Historical handling | Public schema |
|---|---|---|---|
| Agent Security Bundle | `trustweave.dev/bundle/v1alpha2` | `v1alpha1` remains a bounded historical envelope and is accepted by bundle comparison. | [`agent-security-bundle-v1alpha2.schema.json`](../schemas/agent-security-bundle-v1alpha2.schema.json) |
| Bundle diff | `trustweave.dev/bundle-diff/v1alpha2` | `v1alpha1` remains readable by SARIF and risk normalization. | [`bundle-diff-v1alpha2.schema.json`](../schemas/bundle-diff-v1alpha2.schema.json) |
| Risk review | `trustweave.dev/risk-review/v1alpha2` | `v1alpha1` remains a historical schema; create a fresh review before creating new decisions. | [`risk-review-v1alpha2.schema.json`](../schemas/risk-review-v1alpha2.schema.json) |
| Risk baseline | `trustweave.dev/risk-baseline/v1alpha2` | `v1alpha1` decision documents require explicit migration and are not silently reinterpreted. | [`risk-baseline-v1alpha2.schema.json`](../schemas/risk-baseline-v1alpha2.schema.json) |
| Risk suppressions | `trustweave.dev/risk-suppressions/v1alpha2` | `v1alpha1` decision documents require explicit migration and are not silently reinterpreted. | [`risk-suppressions-v1alpha2.schema.json`](../schemas/risk-suppressions-v1alpha2.schema.json) |
| Local attestation | `trustweave.dev/attestation/v1alpha3` | The verifier retains documented local v1alpha1 and v1alpha2 readers. | [`attestation-v1alpha3.schema.json`](../schemas/attestation-v1alpha3.schema.json) |
| Synthetic test results | `trustweave.dev/test-results/v1alpha1` | Current contract. | [`test-results-v1alpha1.schema.json`](../schemas/test-results-v1alpha1.schema.json) |
| Policy, trace, MCP, chain, and framework reviews | Versioned `v1alpha1` contracts | Current contracts are listed in the schema catalog. | [`schemas/`](../schemas/) |

## Bundle migration

Bundle v1alpha2 is the first bundle contract that makes the complete normalized policy payload part of the strict public artifact: classification taxonomy, approval control, advanced rule predicates, findings, limits, and summary counts are all validated. `trustweave scan` in TrustWeave 0.2.0 emits `trustweave.dev/bundle/v1alpha2`.

Historical v1alpha1 bundles retain their original bounded schema and are not relabeled or augmented. `trustweave diff` accepts either supported bundle version and emits `trustweave.dev/bundle-diff/v1alpha2`, recording `base.bundle_schema_version` and `head.bundle_schema_version`. Regenerate a bundle with the current CLI to migrate it; do not edit its version string in place.

> A stable bundle payload changes when declared source or tool identifiers, trust, action classes, classifications, capabilities, policy decisions, severity, rule predicates, required controls, or approval bindings change. Provenance timestamps remain separate from that security-relevant evidence identity.

## Risk-review migration

Risk-review v1alpha2 preserves the canonical `trustweave/fingerprint/v3` identity and adds explicit reviewer-visible lifecycle distinctions. Active states include `new`, expired decisions, `not_yet_applicable_baseline`, `not_yet_applicable_suppression`, `severity_escalated_baseline`, and `severity_escalated_suppression`. A rule-ID or subject-digest mismatch remains active and is reported in `mismatched_decisions`; unused decisions remain in `orphaned_decisions`.

A decision applies only when its fingerprint, `TW-` rule ID, stable subject digest, creation time, expiry, and accepted severity are compatible with the reviewed finding. Future-created and severity-escalated decisions are not treated as missing or silently applied. Create a fresh risk review and baseline draft to move historical review evidence forward.

## Validation layers

TrustWeave does not require `jsonschema` at runtime. Typed parsers validate semantic invariants such as unknown fields, cross-references, bounded collections, classification ranges, approval controls, and decision identity. JSON Schema resources validate structure. The CI `validate` stage invokes typed validation for every configured input, including `baseline_bundle`, `candidate_bundle`, risk decisions, traces, profiles, and safe output paths before any artifact publication.

## Change checklist

A contract change requires a new version whenever it changes a required field, identity, policy decision semantics, review state, or compatibility of a strict existing artifact. The change must include root and packaged schemas, typed validation, real-output conformance tests, installed-wheel discovery, a migration note, and synchronized CLI, configuration, quality, threat-model, and schema documentation. Historical changelog entries describe their own releases and are not rewritten to describe new behavior.
