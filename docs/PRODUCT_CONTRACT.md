# TrustWeave Product Contract

## Outcome

**TrustWeave is a local-first security build tool for developers who add tools or MCP-style integrations to AI agents and need verifiable evidence that a change did not introduce an unsafe trust-boundary path.**

The first release is intentionally narrow. It inventories a declared agent architecture, evaluates deterministic policy invariants against that architecture, runs safe synthetic scenarios, produces a review-friendly Markdown report, and emits a deterministic local evidence bundle. TrustWeave can also emit a separate unsigned hash-linked statement for exact supplied-file consistency; external signing or trusted publication is required for provenance beyond the local workspace.

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
| `trustweave trace-review` | Compares a local trace’s minimized tool-call metadata with declared manifest flows and policy decisions. | `artifacts/trace-review.json`, `artifacts/trace-review.md` |
| `trustweave mcp-profile-check` | Compares a local MCP metadata profile with manifest tool mappings and action classes. | `artifacts/mcp-profile-review.json`, `artifacts/mcp-profile-review.md` |

## Domain model

| Entity | Meaning | Safety invariant |
|---|---|---|
| **Agent manifest** | Declarative local description of sources, tools, data classes, and flows. | It is input data, never executable configuration. |
| **Source** | A point where data or instructions enter an agent workflow. | Every source has an explicit trust label. |
| **Tool** | A declared action endpoint such as retrieval, customer lookup, email, or ticket creation. | Every tool has explicit capabilities and an action class. |
| **Flow** | A declared source-to-tool route. | A policy evaluates every flow; missing labels fail closed. |
| **Policy** | Deterministic allow/deny or approval rule for a flow. | The MVP never delegates enforcement decisions to a language model. |
| **Scenario** | A safe synthetic test case that validates a policy assertion. | No scenario targets external infrastructure or handles real data. |
| **Evidence bundle** | Deterministic JSON document generated from local declarations and policy. | It is not self-authenticating; exact-file consistency is recorded separately in an unsigned hash-linked statement and external signing or trusted publication is required for provenance. |
| **Policy review** | Static report over ordered rules and review-sensitive decisions. | It creates review obligations; it never approves, blocks, or enforces a deployment. |
| **Bundle diff** | Structured comparison of two generated bundles. | It reports declared changes and signals; it never discovers runtime behavior or reports a vulnerability verdict. |
| **Trace review** | Local review of recorded source/tool/event metadata against declared flows and policy. | It omits message content and tool arguments, executes nothing, and does not authenticate or establish completeness of a trace. |
| **MCP metadata profile** | Local declaration of a server transport, resource identifier, authorization expectation, and tool-to-manifest mapping. | It does not discover a server, retrieve metadata, process tokens, validate OAuth, or execute a tool. |

## Explicit safety boundaries

TrustWeave 0.2 source **does not** execute MCP server commands, discover local credentials, make network connections, call models, analyze untrusted repositories, run exploit payloads, scan hosts, test live accounts, collect personal data, or send business actions. Its offline trace review reads only local structured metadata and deliberately excludes message content and tool arguments from review artifacts. Its MCP profile review accepts only local metadata and never performs server discovery, transport access, OAuth, token handling, or capability retrieval.

The project accepts only a local YAML/JSON manifest and fixed synthetic scenarios. It produces deterministic findings based on rules visible in the repository. When data is missing or malformed, the tool reports an error and exits non-zero rather than guessing.

## Quality model

The initial release is complete only when:

1. The documented example produces a valid bundle, deterministic policy results, a report, and an attestation.
2. Unit tests cover manifest validation, policy evaluation, scenario outcomes, report generation, and hash-link verification.
3. The CLI is type-checked, formatted, tested, and packaged locally.
4. The baseline and candidate example produce a deterministic bundle diff and an expected review signal for the newly declared synthetic external tool.
5. The policy-review command reports a clear result for the default policy and structured review findings for covered unsafe test controls.
6. The trace-review command produces a clear result for a declared safe synthetic trace, a review finding for a policy-denied synthetic trace, and omits message content and tool arguments from its report.
7. The MCP profile command produces a clear result for safe synthetic HTTP metadata and review findings for missing authorization expectation, unknown mapping, and action-class drift without contacting a server.
8. Documentation states what the project does, what it does not do, how to verify it, and how to report a security concern.
9. The GitHub workflow defines the exact automated checks without making unsupported production-readiness claims.
10. Maintainers record the exact reviewed SHA, relevant hosted evidence, residual limits, and release-sensitive decision separately from ordinary check status; see [Maintainer Handoff](MAINTAINER_HANDOFF.md).

## Delivery policy

TrustWeave [`0.2.3`](https://pypi.org/project/trustweave/0.2.3/) is the published PyPI package and [GitHub Release `v0.2.3`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.3) targets `4aed7df9d16907804f8c2460c004a4dc685904bc`. Its exact TestPyPI and PyPI wheels passed the documented TestPyPI-first expected-repository verification; [Release Evidence 0.2.3](RELEASE_EVIDENCE_0.2.3.md) preserves the limited file-specific record. Annotated `v0.2.0` remains an immutable unpublished audit record at `7232fe3a23d92f50a693903c0a6b7cb92d0a1426`; it must not be reused or published from. A future release must update version and changelog evidence, pass documented local checks and hosted CI on the exact approved head, use an owner-authorized annotated tag, follow the dedicated publishing workflow, and record its own clean-install plus exact-file provenance evidence. A successful build alone is not release authorization.

## Future scope, deliberately excluded from the current local evidence contract

The following items are valid roadmap candidates but not part of the first vertical slice: MCP proxying, OPA integration, OpenFGA integration, external signature services, automatic source discovery, framework SDKs, dashboards, hosted registries, production telemetry ingestion, and enterprise multitenancy.

## Extension admission rule

A future capability may enter the product contract only after its proposal identifies the user decision it improves, the local or external data boundary, failure behavior, deterministic evidence, compatibility impact, tests, documentation, residual limits, and the maintainer decision required to authorize it. Capabilities that add live execution, network access, credentials, data collection, identity claims, automatic merges, or publication require a separate threat model and owner-approved operating procedure before implementation. Until then, they remain excluded scope rather than hidden optional behavior.
