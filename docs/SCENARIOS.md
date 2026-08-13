# Synthetic Adversarial Scenario Library

TrustWeave’s adversarial scenarios are a **static policy-regression library**, not an attack engine. Each scenario contains only a synthetic source-trust label, a synthetic tool action class, an expected deterministic policy decision, an explanatory rationale, and public reference URLs. No scenario contains a live endpoint, credential, executable tool configuration, adversarial prompt payload, or instruction to access an external system.

> A passing scenario establishes only that the selected local policy produces the expected decision for the declared labels. It does **not** establish that a deployed model, agent, tool, MCP server, or organization is secure.

## Running the library

```bash
trustweave test \
  --policy policies/default-policy.json \
  --scenarios scenarios/adversarial-scenarios.json \
  --output-dir artifacts/adversarial

trustweave explain \
  --scenarios scenarios/adversarial-scenarios.json \
  --scenario-id TW-ADV-001
```

`test` writes ordinary local test evidence. `explain` prints the selected synthetic pattern, rationale, labels, expected decision, and its declared public references without contacting those references.

## Library coverage

| Identifier range | Pattern families | Example policy assertion |
|---|---|---|
| `TW-ADV-001`–`002` | Direct and indirect prompt-injection-shaped context | Untrusted context cannot directly reach an external or sensitive action. |
| `TW-ADV-003` | Tool-description-poisoning-shaped metadata | Untrusted metadata does not authorize an external action. |
| `TW-ADV-004` and `010` | Confused-deputy and approval-boundary paths | Conditional context needs approval before an external action. |
| `TW-ADV-005`, `007`, and `008` | Sensitive-data, prompt-leakage, and retrieval-boundary routes | Untrusted context cannot directly reach sensitive data; conditional outbound context requires approval. |
| `TW-ADV-006` | Excessive-agency-shaped request | Untrusted context cannot directly expand an external action scope. |
| `TW-ADV-009` | Supply-chain-metadata-shaped route | Third-party metadata remains untrusted until explicitly reviewed. |

OWASP describes both direct and indirect prompt injection and recommends segregation of external content, least privilege, human approval for high-risk actions, and adversarial testing.[1] MITRE ATLAS is a living knowledge base of AI adversary tactics and techniques, and OWASP cross-references its direct and indirect LLM prompt-injection techniques.[1] [2] These sources inform the library’s *review vocabulary*, not an executable red-team workflow.

## Add a scenario safely

A new scenario must be represented as a local object in `scenarios/adversarial-scenarios.json`. Its identifier must be unique, its `source_trust`, `tool_action_class`, and `expected_decision` must be supported TrustWeave labels, and each library scenario must contain at least one `https://` public reference. Use an explanatory description rather than exploit steps, payloads, or instructions for contacting a target.

| Required field | Purpose |
|---|---|
| `id` | Stable `TW-ADV-*` identifier for test evidence and CI. |
| `title` and `category` | Human-readable teaching and navigation metadata. |
| `description` | A synthetic architecture pattern, expressed without a payload or live target. |
| `rationale` | Why the expected trust-boundary decision matters. |
| `source_trust`, `tool_action_class`, `expected_decision` | The deterministic policy assertion. |
| `references` | One or more public `https://` taxonomy or standards references. |

Do not present a scenario as evidence of a vulnerability in a real product. If a scenario requires a new policy label or runtime behavior, propose and review that contract separately; do not hide a new execution capability in scenario data.

## Compatibility

Scenario metadata is additive. Existing v1alpha1 packs with only `id`, `description`, `source_trust`, `tool_action_class`, and `expected_decision` continue to parse and run. Their explanations use the identifier and description as fallbacks and state that no taxonomy reference was declared.

## References

[1]: https://genai.owasp.org/llmrisk/llm01-prompt-injection/ "OWASP LLM01:2025 Prompt Injection"
[2]: https://atlas.mitre.org/ "MITRE ATLAS"
[3]: https://modelcontextprotocol.io/specification/2025-03-26/server/tools "MCP tools specification (2025-03-26)"
