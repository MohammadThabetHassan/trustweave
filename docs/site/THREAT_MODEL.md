# Threat model and security boundary

TrustWeave 0.2.0 is a **declarative architecture-review and synthetic-regression tool**. It evaluates explicitly supplied local declarations and local evidence artifacts. It is not a runtime defense, scanner, agent executor, model evaluator, endpoint-discovery tool, or production-security certification.

## What is represented

| Local evidence | Example | TrustWeave behavior |
| --- | --- | --- |
| Source trust and classification | A declared untrusted source with confidential data | Applies deterministic local policy predicates to supplied labels |
| Tool action and capability metadata | An external notification tool with `email.send` | Reviews declared policy and chain relationships without invoking the tool |
| Flow and policy order | A declared source-to-tool route | Evaluates first-match policy decisions and preserves explanation evidence |
| Review artifacts | Bundle, scenario result, chain review, trace metadata, MCP profile, SARIF | Reads or writes local structured files with stated limits |
| Reviewer decisions | Baselines and suppressions | Keeps expiry-bound decisions visible; they do not equal remediation |

## Controls at the declaration layer

TrustWeave validates strict local schemas and typed parser contracts; rejects unsafe local inputs such as symbolic links, invalid UTF-8, oversized/deep documents, unsafe YAML, non-string keys, and undeclared identifier shapes; and applies deterministic policy, chain, risk, and artifact-integrity logic. The repository adds source scanning and pinned workflow dependencies to protect its own implementation boundary.

> A finding is evidence that a supplied declaration needs review. It is not evidence that the declared condition exists in a deployed runtime, that a real approval occurred, or that a system is secure.

## Deliberately out of scope

TrustWeave does not execute declared tools or agents; connect to MCP servers; discover endpoints; read credentials; inspect live environments; auto-load plugins; evaluate arbitrary configuration code; load remote policies or schemas; upload SARIF; post pull-request comments; add telemetry; or enforce runtime controls. It also does not claim to detect prompt injection in real model context, authenticate unsigned files, prove evidence provenance, or replace human review.

## Review expectations

Use TrustWeave from a trusted local checkout with ordinary code review and repository controls. A reviewer should validate declaration changes, inspect generated artifacts and limits, investigate any incomplete chain analysis, and make baseline or suppression decisions explicitly. Evidence sources that contain sensitive metadata require separate data-governance controls before they are placed in a local checkout.

For vulnerability reporting, follow the repository’s [security policy](https://github.com/MohammadThabetHassan/trustweave/blob/main/SECURITY.md). Do not publish credentials, personal data, third-party exploit chains, or instructions that cause harmful external actions.
