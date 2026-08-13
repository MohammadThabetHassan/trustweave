# Agent-Security Ecosystem Review — August 2026

## Research objective

This review assesses established open-source agent-security capabilities that can strengthen TrustWeave without duplicating a runtime governance platform or expanding beyond the project’s safe, non-executing architecture-review boundary.

## Primary findings

| Source | Verified capability | TrustWeave implication |
|---|---|---|
| Microsoft Agent Governance Toolkit | Intercepts runtime tool calls, applies deterministic policies, maintains identity and audit layers, supports policy linting, evidence checks, and multiple framework integrations. [1] | TrustWeave should not duplicate a runtime enforcement engine. It should improve its role as a pre-deployment architecture, policy, and evidence layer that can export inputs suitable for future enforcement adapters. |
| OWASP Agent Security Regression Harness | Uses scenario files, pre-recorded traces, policy assertions, machine-readable results, and CI workflows to catch known agent-security regression classes. [2] | TrustWeave can add a safe **offline trace review** capability for pre-recorded synthetic traces. This preserves non-execution while connecting policy declarations to observed tool-call evidence. |
| Model Context Protocol authorization specification | Defines optional transport-level authorization for MCP, including resource metadata, OAuth authorization, token audience binding, and restrictions on token passthrough. [3] | TrustWeave can add a declarative, non-executing **MCP metadata profile** that records a server’s transport, resource URI, authorization expectation, and declared tool capabilities. It should validate configuration metadata only and never obtain or process real tokens. |
| SLSA attestation model | Defines an attestation as authenticated machine-readable metadata whose statement binds subjects to a predicate; it distinguishes integrity from authenticity and recommends interoperable provenance formats for open source. [4] | TrustWeave should preserve its existing local hash-chain evidence while adding an explicit export shape that is compatible with statement/predicate concepts. It must not call the result signed or externally verifiable until a signing and verification lifecycle is implemented. |

## Candidate enhancements

### 1. Offline trace-policy review — highest product value

A new command should consume a **synthetic or pre-recorded local trace JSON**, never connect to an agent, and compare observed tool calls with the declared manifest and deterministic policy. It should answer: which declared tools were called, were any unexpected tools used, did the trace contain a call that policy would deny or require approval, and did a sensitive/external action occur after untrusted context was observed?

This gives TrustWeave a stronger evidence chain:

> **Declared architecture → deterministic policy → offline observed trace → review report → local evidence artifact**

The command remains safe because it reads local data only. It does not execute a target, send a request, interpret model text as a command, or expose live credentials.

### 2. MCP metadata profile — strong ecosystem fit

A strict JSON schema can model safe, declared MCP metadata: server identifier, transport, canonical resource URI for HTTP, whether authorization is expected, and a list of declared tools mapped to TrustWeave action classes. The tool should validate the document and provide a report that flags missing transport resource URIs, HTTP endpoints declared without authorization expectations, and tool-name drift against an Agent Security Bundle.

This does not claim OAuth compliance, validate a token, discover a server, or establish a connection. It is pre-deployment metadata review.

### 3. Statement-shaped evidence export — future-ready evidence

A local export can shape existing bundle/test/trace results into a generic statement with subject digests, a predicate type, and explicit `unsigned_local_evidence` status. It must retain the distinction between **integrity** and **authenticity**. External DSSE, Sigstore, or SLSA provenance signing should remain a future release because they require identity, key custody, and independent verification decisions.

## Selected enhancement direction

Implement **offline trace-policy review** first. It is the best fit because it adds an observed-evidence layer, interoperates conceptually with regression-harness trace workflows, remains fully local and non-executing, produces deterministic testable output, and improves the project without copying runtime-governance platforms.

MCP metadata profiles and statement-shaped export are the recommended next two modules after trace review is stable.

## References

[1]: https://github.com/microsoft/agent-governance-toolkit "Microsoft Agent Governance Toolkit"
[2]: https://github.com/OWASP/Agent-Security-Regression-Harness "OWASP Agent Security Regression Harness"
[3]: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization "Model Context Protocol Authorization Specification"
[4]: https://slsa.dev/attestation-model "SLSA Attestation Model"


## Trace-contract design notes

The OWASP regression harness documents a framework-neutral trace shape with `messages`, `tool_calls`, and `events`. Tool calls conventionally use `name`, while adapters may normalize alternative `tool` or `tool_name` fields. MCP calls can use source-qualified names such as `mcp/<server_id>/<tool>`. [2]

TrustWeave’s initial trace-review implementation will accept a deliberately constrained local JSON subset:

| Trace element | TrustWeave vNext use | Boundary |
|---|---|---|
| `tool_calls` | Compare observed names with declared manifest tools and evaluate the deterministic policy decision using the source trust recorded in the call or `trusted` only when explicitly declared. | Tool calls are evidence records, never instructions to execute a tool. |
| `events` | Recognize `untrusted_context_received` as an observed trust-boundary fact and report it alongside subsequent sensitive/external calls. | The tool does not parse message content or infer an attack from natural language. |
| `messages` | Retain only message counts in the review summary. | The vNext module will not search, reproduce, classify, or emit message content, avoiding secret and privacy leakage. |
| Unknown fields | Preserve no raw unknown payload data in the report. | The validator rejects malformed required fields and reports structural errors. |

This preserves compatibility at the conceptual data-model level while avoiding live-target execution, adapter loading, network access, token handling, and model-output interpretation.
