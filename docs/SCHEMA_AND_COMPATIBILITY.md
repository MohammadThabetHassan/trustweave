# Schema and Compatibility

## Compatibility policy

TrustWeave treats local manifests, policies, scenarios, bundles, reviews, and attestations as **versioned evidence contracts**. Runtime validation remains dependency-free and authoritative; JSON Schema provides structural interoperability and editor feedback. Every published root schema is byte-identical to its packaged counterpart, and generated output is tested against both resources.

Schema `$id` values and the attestation `predicate_type` use `https://trustweave.dev/` URIs as stable identifiers, not as retrieval locations. Validation resolves schemas from the packaged resources on disk, and matching an artifact against a contract is a string comparison of its version identifier. Nothing in the tool dereferences these URIs, so they are not required to serve a document and the local behavior does not depend on whether they do.

| Artifact | Current published emitted version | Historical handling | Public schema |
|---|---|---|---|
| Agent Security Bundle | `trustweave.dev/bundle/v1alpha2` | `trustweave.dev/bundle/v1alpha1` remains a bounded historical envelope and is accepted by bundle comparison. | [`agent-security-bundle-v1alpha2.schema.json`](../schemas/agent-security-bundle-v1alpha2.schema.json) |
| Bundle diff | `trustweave.dev/bundle-diff/v1alpha3` | Published `0.3.0` emits `trustweave.dev/bundle-diff/v1alpha3`; `trustweave.dev/bundle-diff/v1alpha1` and `trustweave.dev/bundle-diff/v1alpha2` remain readable by SARIF and risk normalization. | [`bundle-diff-v1alpha3.schema.json`](../schemas/bundle-diff-v1alpha3.schema.json) |
| Risk review | `trustweave.dev/risk-review/v1alpha2` | `trustweave.dev/risk-review/v1alpha1` remains a historical schema; create a fresh review before creating new decisions. | [`risk-review-v1alpha2.schema.json`](../schemas/risk-review-v1alpha2.schema.json) |
| Risk baseline | `trustweave.dev/risk-baseline/v1alpha2` | `trustweave.dev/risk-baseline/v1alpha1` decision documents require explicit migration and are not silently reinterpreted. | [`risk-baseline-v1alpha2.schema.json`](../schemas/risk-baseline-v1alpha2.schema.json) |
| Risk suppressions | `trustweave.dev/risk-suppressions/v1alpha2` | `trustweave.dev/risk-suppressions/v1alpha1` decision documents require explicit migration and are not silently reinterpreted. | [`risk-suppressions-v1alpha2.schema.json`](../schemas/risk-suppressions-v1alpha2.schema.json) |
| Local attestation | `trustweave.dev/attestation/v1alpha3` | The verifier retains documented local `trustweave.dev/attestation/v1alpha1` and `trustweave.dev/attestation/v1alpha2` readers. | [`attestation-v1alpha3.schema.json`](../schemas/attestation-v1alpha3.schema.json) |
| Synthetic test results | `trustweave.dev/test-results/v1alpha1` | Current contract. | [`test-results-v1alpha1.schema.json`](../schemas/test-results-v1alpha1.schema.json) |
| Policy review | `trustweave.dev/policy-review/v1alpha2` | `trustweave.dev/policy-review/v1alpha1` remains the published v0.3.0 contract, unchanged, and is still accepted by SARIF export and risk normalization. | [`policy-review-v1alpha2.schema.json`](../schemas/policy-review-v1alpha2.schema.json) |
| Trace, MCP, chain, and framework reviews | Versioned `v1alpha1` contracts | Current contracts are listed in the schema catalog. | [`schemas/`](../schemas/) |

> **Release boundary.** Published `trustweave==0.3.0` emits `trustweave.dev/bundle-diff/v1alpha3`. The historical `v1alpha1` and `v1alpha2` formats remain readable only through the documented bounded readers; historical evidence is not silently relabeled.

## Bundle migration

Bundle v1alpha2 is the first bundle contract that makes the complete normalized policy payload part of the strict public artifact: classification taxonomy, approval control, advanced rule predicates, findings, limits, and summary counts are all validated. `trustweave scan` in TrustWeave 0.2.0 emits `trustweave.dev/bundle/v1alpha2`.

Historical v1alpha1 bundles retain their original bounded schema and are not relabeled or augmented. In published `0.3.0`, `trustweave diff` accepts either supported bundle version and emits `trustweave.dev/bundle-diff/v1alpha3`, recording `base.bundle_schema_version`, `head.bundle_schema_version`, and a normalized policy-only delta. The strictly bounded v1alpha3 policy delta makes security-relevant changes visible even when current declared flow outcomes do not change: fail-closed to fail-open (`TW-DIFF-004`), default to allow (`TW-DIFF-005`), approval-control removal (`TW-DIFF-006`), approval-binding removal (`TW-DIFF-007`), rule-decision weakening (`TW-DIFF-008`), required-control removal (`TW-DIFF-009`), classification-taxonomy change (`TW-DIFF-010`), structural rule-set or matching-boundary changes (`TW-DIFF-011`), and a rule that gained a required control the policy does not declare (`TW-DIFF-012`). The structural signal covers added or removed rules, matching predicates, and potentially order-sensitive first-match changes; it requires human review but does not prove that every reported change is insecure or that every possible policy weakening is detected. Regenerate a bundle with the current CLI to migrate it; do not edit its version string in place.

> A stable bundle payload changes when declared source or tool identifiers, trust, action classes, classifications, capabilities, policy decisions, severity, rule predicates, required controls, or approval bindings change. Provenance timestamps remain separate from that security-relevant evidence identity.

## Policy-review migration

Policy review emits `trustweave.dev/policy-review/v1alpha2`. The v1alpha1 schema is the
published `0.3.0` document and is left exactly as released: the collective-cover fields
`shadowed_by_rules` and `cover_search` had been added to its `required` list under an
unchanged version constant, and because `coverage` and `coverage_result` both set
`additionalProperties: false` that broke validation in both directions — the edited schema
rejected every artifact `0.3.0` emitted, and a consumer pinned to the released schema
rejected every new artifact. `docs/contracts/compatibility-v1.json` classes a new emitted
artifact contract with a documented migration as **minor**, so it takes a new version
rather than a relaxation: making the fields optional would not have helped, because the
released schema's `additionalProperties: false` still rejects an artifact that carries
them.

v1alpha2 adds `coverage_result.shadowed_by_rules` and `coverage_result.cover_search`,
`coverage.declined_rules`, the `rule` key on a rule-level finding subject, and constrains
declared rule identifiers with the same `rule_identifier` pattern the bundle schema uses
rather than the `TW-` finding-identifier pattern. Regenerate a policy review with the
current CLI; do not edit an artifact's version string in place.

## Risk-review migration

Risk-review v1alpha2 carries the canonical `trustweave/fingerprint/v4` identity and adds explicit reviewer-visible lifecycle distinctions. The `v3` namespace is retired: policy-review and declared-chain findings now carry a subject that names the rule, sanitizer, or propagated classifications the finding is about, so their fingerprints changed. A `v3` baseline or suppression document is refused by name rather than silently orphaned — re-run baseline creation against a fresh risk review; never copy a fingerprint string forward. Active states include `new`, expired decisions, `not_yet_applicable_baseline`, `not_yet_applicable_suppression`, `severity_escalated_baseline`, and `severity_escalated_suppression`. A rule-ID or subject-digest mismatch remains active and is reported in `mismatched_decisions`; unused decisions remain in `orphaned_decisions`.

A decision applies only when its fingerprint, `TW-` rule ID, stable subject digest, creation time, expiry, and accepted severity are compatible with the reviewed finding. Future-created and severity-escalated decisions are not treated as missing or silently applied. Create a fresh risk review and baseline draft to move historical review evidence forward.

## Validation layers

TrustWeave does not require `jsonschema` at runtime. Typed parsers validate semantic invariants such as unknown fields, cross-references, bounded collections, classification ranges, approval controls, and decision identity. JSON Schema resources validate structure. The CI `validate` stage invokes typed validation for every configured input, including `baseline_bundle`, `candidate_bundle`, risk decisions, traces, profiles, and safe output paths before any artifact publication.

## Change checklist

A contract change requires a new version whenever it changes a required field, identity, policy decision semantics, review state, or compatibility of a strict existing artifact. The change must include root and packaged schemas, typed validation, real-output conformance tests, installed-wheel discovery, a migration note, and synchronized CLI, configuration, quality, threat-model, and schema documentation. Historical changelog entries describe their own releases and are not rewritten to describe new behavior.
