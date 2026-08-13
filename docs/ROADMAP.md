# TrustWeave Roadmap

## Product direction

TrustWeave’s role is a **local evidence layer for agent-security review**. It should make declared architecture, deterministic policy, safe synthetic regression, and local trace metadata visible before a change reaches production. It should not quietly become an unrestricted agent runner, MCP proxy, exploit tool, credential scanner, or model evaluator.

## Completed foundation

| Capability | Status | Evidence |
|---|---|---|
| Declared source, tool, and flow inventory | Complete | Strict manifest validation and Agent Security Bundle. |
| Deterministic flow-policy evaluation | Complete | First-match policies, synthetic scenarios, and policy review. |
| Change review | Complete | Bundle diff with source, tool, path, rule, and decision signals. |
| Local integrity evidence | Complete | Hash-linked local attestation and verifier. |
| Offline observed-evidence review | Complete in current `main` | Local trace-policy review with privacy-preserving reports and explicit review gate. |
| Static MCP metadata review | Complete in current `main` | Local profile-to-manifest mapping, transport/authorization expectation, and strict non-connection boundary. |
| Quality automation | Complete | Formatting, linting, type check, static source scan, tests, build, isolated wheel, dependency audit, and synthetic evidence workflows. |

## Next planned milestones

### v0.2.0 — publish the verified review workflow

A future `v0.2.0` release should package the current trace-review and documentation work after explicit release authorization. It should include a clean changelog section, release notes, source distribution, wheel, and verification evidence for the final tag.

### v0.3.0 — statement-shaped evidence export

TrustWeave should export existing local evidence into a generic subject/predicate statement shape with explicit `unsigned_local_evidence` status. It must clearly distinguish local integrity from authenticated provenance. External DSSE, Sigstore, or SLSA provenance support requires separate design for identities, key custody, verification, publication, and failure behavior.

### v0.4.0 — review-platform adapters

A narrowly scoped adapter could emit a pull-request-friendly Markdown summary or annotation from existing local artifacts. It should remain opt-in, use least-privilege workflow permissions, never expose message content or tool arguments, and never modify runtime systems.

## Explicitly deferred work

| Capability | Why it is deferred |
|---|---|
| Runtime tool interception | It belongs to an authorization/enforcement layer with identity, availability, rollback, and incident-response requirements. |
| Live agent or MCP execution | It would cross TrustWeave’s non-executing safety boundary and need isolated environments plus explicit user authorization. |
| Prompt injection detection from raw text | It risks false confidence, privacy exposure, and model-dependent classification behavior outside the deterministic core. |
| Automatic vulnerability scanning of third-party skills | It requires a dedicated analysis engine, malicious-input handling, licensing review, and a different threat model. |
| External signing and transparency-log publication | It requires trusted identity, key custody, public verification, and evidence-retention decisions. |
| Multi-tenant service or hosted dashboard | It requires a full privacy, authentication, authorization, data-retention, and operational model. |

## Contribution selection rule

A proposed feature is a good fit only when it improves a reviewer’s ability to understand **declared or pre-recorded local evidence** while preserving deterministic behavior, explicit limits, testability, privacy minimization, and no external side effects.
