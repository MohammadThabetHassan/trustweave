# Concepts and Boundaries

TrustWeave models a reviewable system as **declared evidence**, not as a live autonomous environment. Its parser contracts turn supplied manifests, policies, scenario packs, chain graphs, trace metadata, and MCP profiles into typed local data. Deterministic analyzers then evaluate only those declarations and emit versioned artifacts with explicit limits.

## The evidence model

| Input | Deterministic operation | Output | Deliberate limit |
|---|---|---|---|
| Agent manifest and policy | First-match policy evaluation of declared flows | Agent Security Bundle | No discovery or execution of the agent, model, or tools. |
| Synthetic scenario pack | Regression evaluation of abstract labels | Security test results | Scenarios are data; they do not run prompts, payloads, or integrations. |
| Chain manifest | Bounded propagation over supplied graph edges | Chain review | No proof that a runtime path exists or is complete. |
| Minimized trace metadata | Correlation with declared source, tool, and policy data | Trace review | Contents and arguments are intentionally not inspected or emitted. |
| Local review artifacts | Canonical fingerprinting with explicit expiry decisions | Risk review | A baseline or suppression is not remediation or authority. |
| Generated local files | Stable payload and optional exact-file hash verification | Unsigned local attestation | No signer identity, DSSE envelope, transparency-log inclusion, or SLSA claim. |

## Deterministic decisions

A policy applies rules in declared order. Each rule requires compatible source trust, tool action class, and any declared optional attributes before it matches. The first matching rule determines the decision; otherwise the declared default decision applies. Review artifacts retain the decision, matched rule where applicable, and scope limitations so a reviewer can distinguish a structural observation from a runtime assertion.

## Human review remains required

TrustWeave can create explicit `review_required` findings and can return an intentional nonzero exit code for a configured review gate. It cannot approve a release, verify an approver’s identity, confirm remediation, or block an external deployment. Those actions remain outside this local deterministic boundary.

For the detailed source-of-truth documents, consult the [architecture](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/ARCHITECTURE.md), [threat model](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/THREAT_MODEL.md), and [reviewer workflow](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/REVIEWER_WORKFLOW.md).
