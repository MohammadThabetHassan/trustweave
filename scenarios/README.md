# Scenario catalogue

Every scenario in this directory is a **static label triple** — a source trust level, a tool action class, and the decision the policy must return. TrustWeave replays them against a policy document offline. Nothing here runs an agent, calls a model, opens a socket, or executes tool code; the adversarial cases are named after real attack patterns but are *shaped like* them, not live exploits.

A scenario suite answers one question: **if someone edits the policy, does any trust boundary move without being noticed?**

## Suites

| Suite | File | Cases | Purpose | Fails when |
|---|---|---:|---|---|
| Boundary regressions | `default-scenarios.json` | 5 | The documented walkthrough path used in the README quick start. | A headline example changes behaviour. |
| Adversarial patterns | `adversarial-scenarios.json` | 25 | Attack-shaped flows mapped to OWASP and MITRE ATLAS. | The policy stops blocking a known-bad shape. |
| Decision coverage matrix | `coverage-matrix-scenarios.json` | 12 | Every trust x action combination the model permits, including the permitted baseline. | The policy blocks legitimate work **or** opens an unintended path. |

Run all three:

```bash
for suite in default adversarial coverage-matrix; do
  trustweave test \
    --policy policies/default-policy.json \
    --scenarios scenarios/${suite}-scenarios.json \
    --output-dir artifacts/${suite}
done
```

## Why the coverage matrix exists

The adversarial suite contains no case that expects `allow`. Every one of its 25 cases expects `deny` or `require_approval`, so it measures only one direction: whether bad flows are blocked. A policy that blocks *everything* — including the agent's legitimate work — passes it in full.

Measured against this repository's own policy with the single `allow` rule removed:

| Policy under test | Adversarial (25) | Coverage matrix (12) |
|---|---|---|
| Shipped `default-policy.json` | passed 25/25 | passed 12/12 |
| **Allow rule removed** (blocks all real work) | **passed 25/25** | **failed 11/12** |
| Deny everything | failed | failed 10/12 |
| Allow everything | failed 0/25 | failed 1/12 |

The matrix suite is what makes an over-restrictive policy visible. A security policy that denies every request is trivially safe and completely useless, and only a suite containing permitted flows can tell the two apart.

## Decision coverage matrix

All twelve combinations of the three trust levels and four action classes. The decision column is what `policies/default-policy.json` returns today; the control column is what produces it.

| ID | Source trust | Action class | Expected | Control that produces it |
|---|---|---|---|---|
| `TW-MTX-001` | trusted | read | **allow** | `TW-001` — Allow trusted requests to read-only tools |
| `TW-MTX-002` | trusted | write | **deny** | default `deny` — no rule grants this flow, so it fails closed |
| `TW-MTX-003` | trusted | sensitive | **deny** | default `deny` — no rule grants this flow, so it fails closed |
| `TW-MTX-004` | trusted | external | **deny** | default `deny` — no rule grants this flow, so it fails closed |
| `TW-MTX-005` | conditional | read | **deny** | default `deny` — no rule grants this flow, so it fails closed |
| `TW-MTX-006` | conditional | write | **deny** | default `deny` — no rule grants this flow, so it fails closed |
| `TW-MTX-007` | conditional | sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools |
| `TW-MTX-008` | conditional | external | **require_approval** | `TW-002` — Require approval before conditional confidential data reaches an external action |
| `TW-MTX-009` | untrusted | read | **deny** | default `deny` — no rule grants this flow, so it fails closed |
| `TW-MTX-010` | untrusted | write | **deny** | default `deny` — no rule grants this flow, so it fails closed |
| `TW-MTX-011` | untrusted | sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools |
| `TW-MTX-012` | untrusted | external | **deny** | `TW-004` — Deny untrusted input to external actions |

Ten of the twelve resolve to `deny`. That is the intended shape: the policy grants narrowly and everything undeclared fails closed.

## Adversarial patterns

25 attack-shaped flows. **Threat class** is what the case targets, **Boundary it defends** is the principle at stake, and **Control that answers it** is the rule that actually decides the flow.

| ID | Pattern | Threat class | Boundary it defends | Flow | Expected | Control that answers it | References |
|---|---|---|---|---|---|---|---|
| `TW-ADV-001` | Indirect prompt-injection-shaped retrieved context | `prompt-injection` | External content must remain untrusted and must not directly authorize an outbound action. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)<br>[ATLAS AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) |
| `TW-ADV-002` | Direct prompt-injection-shaped privileged request | `prompt-injection` | A request classified as untrusted must not gain direct access to sensitive capabilities. | untrusted → sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools | [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)<br>[ATLAS AML.T0051.000](https://atlas.mitre.org/techniques/AML.T0051.000) |
| `TW-ADV-003` | Tool-description poisoning-shaped outbound request | `tool-misuse` | MCP tool annotations and descriptions are metadata, not authorization; untrusted declarations need explicit policy control. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [MCP tools spec](https://modelcontextprotocol.io/specification/2025-03-26/server/tools) |
| `TW-ADV-004` | Confused-deputy-shaped cross-boundary action | `authorization-boundary` | Conditional context requires a documented approval boundary before a high-impact external action. | conditional → external | **require_approval** | `TW-002` — Require approval before conditional confidential data reaches an external action | [OWASP Agent Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) |
| `TW-ADV-005` | Sensitive-information-disclosure-shaped route | `sensitive-data` | A data-disclosure-shaped route should require explicit human approval rather than an automatic outbound decision. | conditional → external | **require_approval** | `TW-002` — Require approval before conditional confidential data reaches an external action | [OWASP LLM02](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) |
| `TW-ADV-006` | Excessive-agency-shaped capability request | `excessive-agency` | Least-privilege architecture keeps untrusted context from directly expanding an agent’s action authority. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [OWASP LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) |
| `TW-ADV-007` | System-prompt-leakage-shaped sensitive access | `sensitive-data` | Prompt or configuration disclosure risk does not grant authority to access protected data. | untrusted → sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools | [OWASP LLM07](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/) |
| `TW-ADV-008` | Vector-retrieval-weakness-shaped sensitive route | `retrieval-boundary` | Retrieved content must remain segregated from authority to invoke sensitive actions. | untrusted → sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools | [OWASP LLM08](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/) |
| `TW-ADV-009` | Supply-chain-metadata-shaped external capability | `supply-chain` | Third-party metadata must be reviewed as a declared trust boundary, not treated as an authority grant. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [OWASP LLM03](https://genai.owasp.org/llmrisk/llm032025-supply-chain/) |
| `TW-ADV-010` | High-impact approval-bypass-shaped path | `approval-boundary` | High-impact actions need an explicit approval decision rather than automatic execution from conditionally trusted context. | conditional → external | **require_approval** | `TW-002` — Require approval before conditional confidential data reaches an external action | [OWASP Agent Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)<br>[MCP tools spec](https://modelcontextprotocol.io/specification/2025-03-26/server/tools) |
| `TW-ADV-011` | MCP tool-list drift-shaped external action | `mcp-drift` | A changed tool list is review metadata and cannot automatically expand authority. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [MCP tools spec (listChanged)](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) |
| `TW-ADV-012` | Tool-name-collision-shaped sensitive action | `mcp-supply-chain` | Tool names and descriptions cannot substitute for explicit trust mapping and policy review. | untrusted → sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools | [OWASP Agent Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) |
| `TW-ADV-013` | Supplier-provenance-drift-shaped capability request | `supply-chain` | Third-party provenance changes require review and do not grant a new action path. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [OWASP LLM03](https://genai.owasp.org/llmrisk/llm03-training-data-poisoning/) |
| `TW-ADV-014` | MCP tool redefinition-shaped sensitive route | `mcp-drift` | A declared tool change requires review and cannot retain prior authority by name alone. | untrusted → sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools | [MCP tools spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) |
| `TW-ADV-015` | Open-world hint-shaped outbound route | `mcp-metadata` | Tool annotations are metadata rather than a policy authorization grant. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [MCP tools spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) |
| `TW-ADV-016` | Resource-link-shaped sensitive disclosure | `resource-boundary` | A resource link must remain untrusted until a declared review boundary is satisfied. | untrusted → sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools | [OWASP Agent Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) |
| `TW-ADV-017` | Multi-agent delegation-shaped external action | `multi-agent` | Delegation cannot cross a trust boundary without explicit authorization and review. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [OWASP Agent Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) |
| `TW-ADV-018` | Approval-record manipulation-shaped action | `approval-boundary` | High-impact approvals must stay bound and fail closed rather than becoming automatic execution. | conditional → external | **require_approval** | `TW-002` — Require approval before conditional confidential data reaches an external action | [OWASP Agent Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) |
| `TW-ADV-019` | Typosquatted tool-name-shaped route | `supply-chain` | Similarity of a tool name is not identity, provenance, or authorization evidence. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [OWASP LLM03](https://genai.owasp.org/llmrisk/llm03-training-data-poisoning/) |
| `TW-ADV-020` | Capability-growth-shaped sensitive route | `capability-drift` | New declared capability scope requires review and cannot be authorized by stale policy assumptions. | untrusted → sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools | [OWASP Agent Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) |
| `TW-ADV-021` | Tool-result poisoning-shaped outbound request | `tool-output` | Tool results are data and must not independently authorize downstream actions. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [OWASP Agent Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) |
| `TW-ADV-022` | Memory-poisoning-shaped sensitive route | `memory-boundary` | Persisted context must not convert untrusted content into privileged authority. | untrusted → sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools | [OWASP Agent Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) |
| `TW-ADV-023` | Supplier-maintenance-drift-shaped external route | `supply-chain` | Supplier maintenance state and metadata require explicit review rather than implicit trust. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions | [OWASP LLM03](https://genai.owasp.org/llmrisk/llm03-training-data-poisoning/) |
| `TW-ADV-024` | Human-preview-bypass-shaped action | `approval-boundary` | A conditional high-impact action stays pending human approval rather than becoming automatic. | conditional → external | **require_approval** | `TW-002` — Require approval before conditional confidential data reaches an external action | [OWASP Agent Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) |
| `TW-ADV-025` | Cross-server tool confusion-shaped sensitive action | `mcp-multi-server` | A tool reference must be explicitly mapped; server context and a familiar label are insufficient. | untrusted → sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools | [MCP tools spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) |

## Boundary regressions

The five flows behind the README quick start.

| ID | Description | Flow | Expected | Control that answers it |
|---|---|---|---|---|
| `TW-SC-001` | A trusted request may use a declared read-only retrieval action. | trusted → read | **allow** | `TW-001` — Allow trusted requests to read-only tools |
| `TW-SC-002` | Conditional confidential context requires approval before a mock external action. | conditional → external | **require_approval** | `TW-002` — Require approval before conditional confidential data reaches an external action |
| `TW-SC-003` | Untrusted retrieved text cannot directly cause an external mock action. | untrusted → external | **deny** | `TW-004` — Deny untrusted input to external actions |
| `TW-SC-004` | Untrusted content cannot directly cause sensitive data access. | untrusted → sensitive | **deny** | `TW-003` — Deny untrusted or conditional input to sensitive tools |
| `TW-SC-005` | An unmatched conditional write flow fails closed under the default policy. | conditional → write | **deny** | default `deny` — no rule grants this flow, so it fails closed |

## What these scenarios do not establish

- **No agent runs.** A pass means the policy document returns the expected decision for a label triple. It does not mean a deployed agent behaves this way.
- **The attack names are shapes, not exploits.** `TW-ADV-001` is not a prompt injection; it is an untrusted-source-to-external-action flow of the kind indirect prompt injection produces.
- **Trust labels are supplied, not derived.** TrustWeave takes the manifest's word for what is trusted. A mislabelled source produces a confident, wrong answer.
- **Coverage is over declared labels only.** The matrix is complete across three trust levels and four action classes; it says nothing about a flow whose labels are missing from the manifest.

## Adding a scenario

Add the case to the suite it belongs to, then run that suite. A new pattern needs `id`, `title`, `category`, `description`, `rationale`, `source_trust`, `tool_action_class`, `expected_decision`, and at least one reference. If you change how many cases a suite holds, update `tests/test_adversarial_scenarios.py` and the count marker `scripts/reality_check.py` looks for.

Adding an attack-shaped case is the easy half. If it expects `deny`, ask what legitimate flow the same rule change would break, and add that case to the coverage matrix too.
