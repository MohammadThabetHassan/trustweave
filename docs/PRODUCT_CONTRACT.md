# TrustWeave Product Contract

## Outcome

**TrustWeave is a local-first security build tool for developers who add tools or MCP-style integrations to AI agents and need verifiable evidence that a change did not introduce an unsafe trust-boundary path.**

The first release is intentionally narrow. It inventories a declared agent architecture, evaluates deterministic policy invariants against that architecture, runs safe synthetic scenarios, produces a review-friendly Markdown report, and emits a tamper-evident local evidence bundle.

## Primary user decision

Before merging an agent change, a developer needs to decide whether a newly declared source, tool, sink, capability, or data-flow edge creates an unacceptable path. TrustWeave provides evidence for that decision; it does not replace human review, authorization systems, security architecture review, or penetration testing.

## MVP contract

| Workflow | Expected outcome | Evidence |
|---|---|---|
| `trustweave scan` | Loads and validates an agent manifest, builds an Agent Security Bundle, and identifies declared trust-boundary paths. | `artifacts/agent-security-bundle.json` |
| `trustweave test` | Runs a fixed set of harmless synthetic scenarios against declared policy invariants. | `artifacts/security-test-results.json` |
| `trustweave attest` | Creates a hash-chained local evidence statement covering the bundle, policy, test result, and current source revision. | `artifacts/attestation.json` |
| `trustweave report` | Writes a human-readable report that explains findings, evidence, and limits. | `artifacts/report.md` |
| `trustweave policy-check` | Reviews ordered policy structure and declared decisions requiring human scrutiny. | `artifacts/policy-review.json`, `artifacts/policy-review.md` |
| `trustweave diff` | Compares a baseline and candidate Agent Security Bundle for declared changes. | `artifacts/bundle-diff.json`, `artifacts/bundle-diff.md` |

## Domain model

| Entity | Meaning | Safety invariant |
|---|---|---|
| **Agent manifest** | Declarative local description of sources, tools, data classes, and flows. | It is input data, never executable configuration. |
| **Source** | A point where data or instructions enter an agent workflow. | Every source has an explicit trust label. |
| **Tool** | A declared action endpoint such as retrieval, customer lookup, email, or ticket creation. | Every tool has explicit capabilities and an action class. |
| **Flow** | A declared source-to-tool route. | A policy evaluates every flow; missing labels fail closed. |
| **Policy** | Deterministic allow/deny or approval rule for a flow. | The MVP never delegates enforcement decisions to a language model. |
| **Scenario** | A safe synthetic test case that validates a policy assertion. | No scenario targets external infrastructure or handles real data. |
| **Evidence bundle** | Hash-linked JSON document generated from local artifacts. | It proves local artifact integrity only; it is not a substitute for external signing or audit. |
| **Policy review** | Static report over ordered rules and review-sensitive decisions. | It creates review obligations; it never approves, blocks, or enforces a deployment. |
| **Bundle diff** | Structured comparison of two generated bundles. | It reports declared changes and signals; it never discovers runtime behavior or reports a vulnerability verdict. |

## Explicit safety boundaries

TrustWeave v0.1 **does not** execute MCP server commands, discover local credentials, make network connections, call models, analyze untrusted repositories, run exploit payloads, scan hosts, test live accounts, collect personal data, or send business actions.

The project accepts only a local YAML/JSON manifest and fixed synthetic scenarios. It produces deterministic findings based on rules visible in the repository. When data is missing or malformed, the tool reports an error and exits non-zero rather than guessing.

## Quality model

The initial release is complete only when:

1. The documented example produces a valid bundle, deterministic policy results, a report, and an attestation.
2. Unit tests cover manifest validation, policy evaluation, scenario outcomes, report generation, and hash-link verification.
3. The CLI is type-checked, formatted, tested, and packaged locally.
4. The baseline and candidate example produce a deterministic bundle diff and an expected review signal for the newly declared synthetic external tool.
5. The policy-review command reports a clear result for the default policy and structured review findings for covered unsafe test controls.
6. Documentation states what the project does, what it does not do, how to verify it, and how to report a security concern.
7. The GitHub workflow defines the exact automated checks without making unsupported production-readiness claims.

## Delivery policy

The user has requested a **private** GitHub repository and direct commits to `main`. No commit or push may occur until explicit commit name and email address information is supplied for every requested attribution identity. No release will be published until the repository is created, verified checks pass, and release authorization is explicit.

## Future scope, deliberately excluded from v0.1

The following items are valid roadmap candidates but not part of the first vertical slice: MCP proxying, OPA integration, OpenFGA integration, external signature services, automatic source discovery, framework SDKs, dashboards, hosted registries, production telemetry ingestion, and enterprise multitenancy.
