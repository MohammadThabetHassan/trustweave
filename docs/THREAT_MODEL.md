# TrustWeave Threat Model

## Purpose

This document defines what TrustWeave v0.1 is designed to help a developer review, what it does not defend, and how the project avoids creating an unsafe scanning or red-team capability.

TrustWeave is a **declarative architecture-review and synthetic-regression tool**, not a runtime defense product.

## Assets represented in the MVP

| Asset | Example | How TrustWeave treats it |
|---|---|---|
| Source trust label | A user request or retrieved document | Explicitly declared as trusted, untrusted, or conditional. |
| Data classification | Public article or synthetic confidential record | Recorded as manifest context; v0.1 does not process the data itself. |
| Tool capability | Read knowledge base, read customer record, send mock email | Declared as a named capability and action class. |
| Flow | Untrusted document influencing an outbound tool action | Evaluated by an ordered, deterministic policy. |
| Policy state | Rule requiring approval for a conditional-to-external path | Versioned input to the generated evidence. |
| Security evidence | Bundle, test results, attestation, report | Local structured output with stated integrity limits. |

## Threats addressed at the declaration layer

| Threat pattern | MVP response | Limit |
|---|---|---|
| Untrusted content is declared as reaching an external action | A deterministic rule can deny the declared path. | It cannot discover undeclared paths or stop a separate runtime. |
| Confidential or conditional data is declared as reaching an external action | A rule can require approval. | It does not implement approval or verify real identity. |
| A policy weakens or a new flow is added | The generated bundle and synthetic tests provide a reviewable diffable artifact. | PR diff rendering is a future integration. |
| A scenario unexpectedly changes decision | The test command returns non-zero on failed expected decisions. | The scenario covers only its declared labels, not full model behavior. |
| A generated evidence document is manually edited | The verifier detects a mismatch in the attestation’s internal hash chain. | It cannot prove the original operator or protect unsigned files from replacement. |

## Out of scope threats

TrustWeave v0.1 does not claim to detect, exploit, or prevent any of the following directly:

- Prompt-injection payloads in real documents or model context.
- Malicious MCP servers, skills, packages, plugins, or repository content.
- Credential theft, data exfiltration, endpoint compromise, persistence, or malware.
- Network vulnerabilities, cloud misconfiguration, IAM errors, or authorization bypass in a live environment.
- Policy bypasses in an agent runtime that has not integrated a future TrustWeave enforcement adapter.
- Tampering by an actor that can modify all generated files and regenerate the local attestation.
- Model deception, model hallucination, or agent-planning behavior.

## Attacker model

The MVP assumes a reviewer uses TrustWeave on a trusted local checkout of the repository. A malicious actor may attempt to add a tool, broaden an action capability, create a new flow from untrusted content, remove a policy rule, or alter a synthetic scenario’s expected outcome. TrustWeave makes those declared changes explicit in versioned artifacts but relies on ordinary code review, repository controls, and CI to prevent unreviewed changes.

TrustWeave does **not** assume manifests from third parties are safe to execute. It therefore never treats them as executable configuration. The implementation parses JSON or safe YAML only and does not launch commands, import plugins, resolve external references, or contact a server.

## Security controls in the repository

| Control | Purpose |
|---|---|
| Strict schema-like validation | Prevents unknown sources/tools and invalid labels from becoming implicit policy inputs. |
| Default decision | Makes unmatched flow decisions explicit and configurable. |
| Synthetic-only scenarios | Allows regression testing without attacks or external side effects. |
| Hash-linked artifacts | Makes local evidence relationships independently checkable. |
| Explicit limits in every artifact | Discourages overclaiming and security theatre. |
| CI workflow | Repeats formatting, lint, typing, and tests on changes. |
| Dependency review workflow | Reviews dependency changes before they are merged in hosted workflows. |

## Reporting a weakness

Please follow [SECURITY.md](../SECURITY.md). Do not file public issues containing personal data, credentials, exploit chains against third parties, or instructions that would cause harmful external actions.
