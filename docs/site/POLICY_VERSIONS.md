# Policy versions and declared controls

TrustWeave accepts two local policy contracts. A policy defines deterministic decisions for declared flows; it does not configure or enforce a runtime access-control system.

| Contract | Status | Additional capabilities |
| --- | --- | --- |
| `trustweave.dev/v1alpha1` | Supported legacy contract | Ordered rules, exact source classifications, capability patterns, and an optional approval-control declaration |
| `trustweave.dev/policy/v1alpha2` | Current policy contract | A bounded classification taxonomy, source/tool identifier predicates, purpose tags, classification ranges, and required declared controls |

Every policy requires a name, a `default_decision`, and its ordered rules. A rule requires its identifier, description, source trust labels, tool action classes, decision, and rationale. Evaluation selects the **first matching rule**; if no rule matches, the policy's `default_decision` applies.

## v1alpha2 predicates

`v1alpha2` provides the following additive constraints. Each supplied constraint must match in addition to the required source trust and tool action-class predicates.

| Field | Meaning |
| --- | --- |
| `classification_taxonomy` | Ordered, non-empty classification set used by exact and range checks |
| `source_identifiers` / `tool_identifiers` | Lowercase ASCII identifiers matching declared manifest names |
| `purpose_tags` | Lowercase ASCII tags that must be declared on the reviewed flow |
| `source_data_classification_at_least` / `_at_most` | Inclusive bounds in the declared taxonomy order |
| `required_controls` | Static declared-policy controls required for a rule to be possible |

Capabilities may be exact values or a final namespace wildcard such as `storage.*`; other glob patterns are rejected. Identifier values are bounded to 64 ASCII characters. Rule identifiers may use uppercase ASCII to support established IDs such as `TW-POL-001`.

## Approval controls

A policy that returns `require_approval` can declare `approval_control` with a design-time `mechanism`, a non-empty `binds_to` list, and an explicit boolean `fail_closed` state. Policy review checks that approval-dependent rules have a complete declared control contract. This declaration is review evidence; it is not proof of a live approval workflow, approver identity, or enforcement behavior.

## Review policy structure

```shell
trustweave policy-check \
  --policy policies/default-policy.json \
  --output-dir artifacts/policy-review
```

Policy review reports impossible predicates, shadowed rules, conflicting decisions, and redundant rules using the same predicate model as flow evaluation. Static `required_controls` determine whether a rule is possible; they do not represent a per-flow dimension for shadow analysis. See [policy review and coverage](POLICY_REVIEW.md) for the finding workflow and [schema catalog](SCHEMAS.md) for packaged schema discovery.
