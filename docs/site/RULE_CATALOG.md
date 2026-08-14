# Built-in Rule Catalog

TrustWeave finding identifiers are stable labels for **review of supplied local declarations and evidence metadata**. They do not establish a vulnerability, incident, runtime exploit path, deployed control state, or authorization outcome. Policy-rule IDs supplied by a user remain user-owned declarations and are not included in this catalog.

## Declared chain review

| Identifier | Local trigger | Reviewer action |
|---|---|---|
| `TW-CHAIN-001` | A declared path from an untrusted source reaches a sensitive classification and a declared external action. | Confirm the declared graph, classification, boundary ownership, and policy intent. |
| `TW-CHAIN-002` | Such a declared sensitive path lacks a fail-closed approval state scoped to its propagated classification. | Confirm that approval is required and binds to the relevant declared scope. |
| `TW-CHAIN-003` | A declared sanitizer does not claim coverage for every propagated sensitive classification. | Review the sanitizer’s stated coverage and any residual classification. |
| `TW-CHAIN-004` | A configured local traversal budget is exceeded, making the graph review incomplete. | Increase an explicit budget only after reviewing input scale; do not treat an incomplete review as clear. |

## Static policy review

| Identifier | Local trigger | Reviewer action |
|---|---|---|
| `TW-POL-001` | The supplied policy has an `allow` default decision. | Confirm that the default is intentional and appropriately bounded. |
| `TW-POL-002` | A rule is structurally shadowed by an earlier deterministic rule. | Reorder, narrow, or remove the later declaration. |
| `TW-POL-003` | A supplied rule permits an untrusted sensitive or external action. | Confirm the policy rationale and human-control boundary. |
| `TW-POL-004` | A high-impact approval path has no declared approval control. | Declare the control or revise the path policy. |
| `TW-POL-005` | A declared approval control lacks required binding fields. | Bind the approval to actor, tool, target, parameters, issuance, and expiry as applicable. |
| `TW-POL-006` | A declared approval control is fail-open. | Review whether a fail-closed control is required for the stated path. |

## Trace and MCP metadata review

| Identifier | Local trigger | Reviewer action |
|---|---|---|
| `TW-TRACE-001` | A supplied trace call names an undeclared manifest source. | Reconcile minimized trace metadata with the declared source inventory. |
| `TW-TRACE-002` | A supplied trace call names an undeclared manifest tool. | Reconcile minimized trace metadata with the declared tool inventory. |
| `TW-TRACE-003` | A source-tool pair appears in supplied trace metadata but is not a declared flow. | Review the declaration and the provenance of the local trace. |
| `TW-TRACE-004` | A declared trace call matches a deterministic `deny` decision. | Investigate the mismatch through the human review process; TrustWeave takes no action. |
| `TW-TRACE-005` | A declared trace call matches `require_approval`. | Verify the relevant approval evidence outside TrustWeave’s local metadata boundary. |
| `TW-MCP-001` | An HTTP MCP profile declares `authorization_expected: false`. | Review whether unauthenticated transport is intentional and protected. |
| `TW-MCP-002` | An MCP profile mapping names an unknown manifest tool. | Correct or review the static mapping. |
| `TW-MCP-003` | An MCP profile action class disagrees with its mapped manifest tool. | Reconcile the declared classifications. |

## Bundle-diff signals

| Identifier | Local trigger | Reviewer action |
|---|---|---|
| `TW-DIFF-001` | A sensitive or external declared tool is added or changed between supplied bundles. | Review its declared capabilities and policy coverage. |
| `TW-DIFF-002` | A supplied head bundle adds or changes an untrusted path to a sensitive or external tool that is not denied. | Review the decision and human-control boundary. |
| `TW-DIFF-003` | An existing sensitive or external tool gains declared capabilities. | Review least privilege and policy coverage. |

## Risk-review states

Risk lifecycle output uses `risk_state` rather than a rule identifier. `new`, `expired_baseline`, and `expired_suppression` remain active reviewer obligations; `baselined` and `suppressed` are explicit, expiry-limited local decisions. These states neither remediate nor waive a security condition. See the [repository risk-management guide](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/RISK_MANAGEMENT.md) for fingerprint, expiry, and decision-document contracts.
