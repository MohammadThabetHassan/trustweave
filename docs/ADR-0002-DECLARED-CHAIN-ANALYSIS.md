# ADR-0002: Bounded Declared Chain Analysis

## Status

Accepted for the additive `trustweave.dev/chain-manifest/v1alpha1` contract.

## Context

TrustWeave evaluates local declarations and supplied metadata; it does not execute an agent, inspect a live topology, discover endpoints, invoke tools, or infer behavior from natural-language descriptions. Reviewers nevertheless need a repeatable way to identify explicitly declared paths that combine untrusted content, sensitive data, and external actions.

Extending the existing agent-manifest contract would silently change a stable v1alpha1 input surface. This decision therefore introduces a separate, optional chain-manifest contract that can coexist with legacy manifests. The chain manifest represents only reviewer-supplied nodes, directed propagation edges, and declared approval or sanitization boundaries.

## Decision

The analyzer traverses a bounded directed graph from a node explicitly marked `trust: untrusted`. It records only simple paths that explicitly include a data node classified `confidential` or `restricted` and a tool or sink explicitly marked `action_class: external`. It does not infer sensitive data, side effects, controls, or reachability from node names or descriptions.

| Topic | Decision |
|---|---|
| Traversal | Deterministic depth-first traversal over sorted node identifiers and edges; cycles are not followed twice in one path. |
| Path identity | A path is the ordered list of declared node identifiers. Traversal state retains this identity, so distinct declared routes are never silently merged merely because their propagated metadata is equal. |
| Approval | A fail-closed approval covers only the sensitive classifications already present at that approval node. Data acquired later is unapproved until a later declared approval covers it. `TW-CHAIN-002` reports each unapproved classification reaching an external action. It is design-time evidence, not proof of runtime approval enforcement. |
| Sanitization | A sanitizer can cover only classifications it explicitly lists. An intervening sanitizer missing the propagated classification produces `TW-CHAIN-003`; no sanitizer is treated as an absent mitigation, not an insufficient sanitizer finding. |
| Budget | Defaults cap nodes, paths, edges, depth, and explored states. Exceeding any budget emits `TW-CHAIN-004` and preserves the limitation rather than claiming exhaustive analysis. |
| Compatibility | Legacy agent manifests remain unchanged. Chain analysis accepts only the additive chain-manifest schema. |

## Consequences

`TW-CHAIN-001` identifies an explicitly declared untrusted-to-sensitive-to-external path. `TW-CHAIN-002` identifies such a path without a declared fail-closed approval boundary. `TW-CHAIN-003` identifies an explicit sanitizer whose declared coverage does not include the propagated classification. These are reviewer obligations based on supplied local declarations, not exploit findings, runtime traces, or security conclusions.

The JSON result includes structured paths suitable for local reporting and SARIF conversion. The CLI must preserve path and node budgets, make budget limitations visible, and perform no network, model, tool, credential, or discovery operation.
