# Manifest contract, purpose tags, and classifications

An agent manifest is a local, non-executable declaration using `trustweave.dev/v1alpha1`. It records the trust boundaries a reviewer wants TrustWeave to evaluate. A valid manifest must contain a name, description, at least one source, at least one tool, and at least one flow.

| Declaration | Required fields | Allowed values or constraint |
| --- | --- | --- |
| Source | `name`, `trust`, `data_classification`, `description` | Trust is `trusted`, `untrusted`, or `conditional` |
| Tool | `name`, `action_class`, `capabilities`, `description` | Action class is `read`, `write`, `sensitive`, or `external`; capabilities are non-empty |
| Flow | `source`, `tool`, `purpose` | The source and tool must refer to manifest declarations; `purpose_tags` is optional |

Source names, tool names, and purpose tags are lowercase ASCII identifiers of at most 64 characters: they start with a letter and may then contain lowercase letters, digits, underscores, or hyphens. Each source and tool name is unique; a flow's purpose tags are also unique.

## Purpose tags

`purpose` is a required human-readable description. `purpose_tags` is the optional, stable machine-readable counterpart that a `policy/v1alpha2` rule may require. Tags support an explicit link between a declared flow and policy intent without interpreting prose.

```json
{
  "source": "support_ticket",
  "tool": "case_export",
  "purpose": "Export an approved support case",
  "purpose_tags": ["support-case", "approved-export"]
}
```

A purpose tag is not a runtime label, authorization decision, data-flow proof, or assurance that the prose accurately describes a deployed system. It is simply a validated declared predicate.

## Classification taxonomy

A source's `data_classification` is a non-empty declared string. In a legacy policy, a rule can match an exact declared classification. In `policy/v1alpha2`, policy authors declare an ordered `classification_taxonomy`; every v1alpha2 exact classification and range boundary must come from that taxonomy. The default taxonomy, when none is supplied by a supported legacy policy, is `public`, `internal`, `confidential`, and `restricted`.

> Classification labels describe supplied declarations. TrustWeave does not inspect data content, infer sensitivity, discover undisclosed sources, or validate an enterprise data-classification program.

Run `trustweave scan --manifest <manifest> --policy <policy> --output-dir <directory>` to evaluate a manifest against a policy. Use [policy versions and controls](POLICY_VERSIONS.md) to match tags and classifications in a v1alpha2 policy, and use [schema catalog](SCHEMAS.md) to inspect the packaged JSON schema.
