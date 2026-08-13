# TrustWeave Roadmap

## Product direction

TrustWeave is a **local evidence layer for AI-agent trust-boundary review**. It makes declared architecture, deterministic policy, synthetic regression, and pre-recorded local metadata visible before a change reaches production. It must not become an unrestricted agent runner, MCP proxy, exploit tool, credential scanner, model evaluator, or live infrastructure scanner.

## Completed foundation

| Capability | Status | Evidence |
|---|---|---|
| Declared source, tool, and flow inventory | Complete | Strict manifest validation and Agent Security Bundle. |
| Deterministic flow-policy evaluation | Complete | First-match policies, synthetic scenarios, and policy review. |
| Change review | Complete | Bundle diff with source, tool, capability, path, rule, and decision signals. |
| Local integrity evidence | Complete | Hash-linked local attestation and verifier. |
| Offline observed-evidence review | Complete | Local trace-policy review with privacy-preserving reports and explicit review gate. |
| Static MCP metadata review | Complete | Local profile-to-manifest mapping, transport/authorization expectation, and strict non-connection boundary. |
| Static MCP tools-list inventory | Complete | Strict normalization of an already-provided `tools/list` snapshot; no discovery, connection, or action-class inference. |
| Cited synthetic adversarial scenarios | Complete | Ten OWASP/MITRE/MCP-shaped label-only scenarios, deterministic expectations, and local `explain` output. |
| Interoperable review export | Complete | Deterministic local SARIF 2.1.0 generation with no automatic upload. |
| Quality automation | Complete | 90% branch coverage, property-based fail-closed tests, formatting, linting, type checks, static source scan, package checks, wheel reproducibility, SBOM, dependency audit, and hosted Python compatibility checks. |
| Governance baseline | Complete | Maintainer decision contract, review cadence, and best-effort private-report acknowledgement objective. |

## Current planned milestones

### v0.2.0 — publish the verified review workflow

A future `v0.2.0` release should package the current reviewed work after explicit release authorization. It should include a clean changelog section, release notes, source distribution, wheel, verification evidence for the final tag, and an owner decision on TestPyPI/PyPI distribution.

### v0.3.0 — statement-shaped evidence export

TrustWeave should export existing local evidence into a generic subject/predicate statement shape with explicit `unsigned_local_evidence` status. It must distinguish local integrity from authenticated provenance. External DSSE, Sigstore, or SLSA support requires separate design for identities, key custody, verification, publication, and failure behavior.

### v0.4.0 — review-platform adapters

A narrowly scoped adapter could emit a pull-request-friendly Markdown summary or annotation from existing local artifacts. It should remain opt-in, use least-privilege workflow permissions, never expose message content or tool arguments, and never modify runtime systems. Any posting or code-scanning upload requires separate owner authorization.

### v0.5.0 — expanded declarative scenario and importer coverage

Extend the cited synthetic scenario library and add file-only importers for carefully selected agent-framework declaration formats. Each importer must accept an already-provided local file, perform strict validation, preserve source provenance and limits, and avoid framework execution, endpoint discovery, credential access, or automatic authorization mapping.

## Actions requiring explicit owner authorization

| Action | Why a code change alone is insufficient |
|---|---|
| Make the repository public | Changes the visibility and exposure of repository history and files. |
| Publish to TestPyPI or PyPI | Creates an external distribution and requires publishing credentials and release approval. |
| Create public issues, labels, PR comments, release notes, or promotional posts | Performs collaborative or public external actions. |
| Upload SARIF to a code-scanning service | Requires an authorized service integration and repository permissions. |
| Sign artifacts with Sigstore/cosign | Requires an identity/key-custody and release-verification policy. |
| Apply for an OpenSSF badge or fiscal sponsorship | Requires external attestations and maintainership commitments. |

## Explicitly deferred work

| Capability | Why it is deferred |
|---|---|
| Runtime tool interception | It belongs to an authorization/enforcement layer with identity, availability, rollback, and incident-response requirements. |
| Live agent or MCP execution | It would cross TrustWeave’s non-executing safety boundary and need isolated environments plus explicit user authorization. |
| Prompt injection detection from raw text | It risks false confidence, privacy exposure, and model-dependent classification behavior outside the deterministic core. |
| Automatic vulnerability scanning of third-party skills | It requires a dedicated analysis engine, malicious-input handling, licensing review, and a different threat model. |
| Source-distribution byte reproducibility | Fixed-epoch wheel reproducibility is implemented; compressed sdist metadata requires a separate deterministic-packaging design. |
| Multi-tenant service or hosted dashboard | It requires a full privacy, authentication, authorization, data-retention, and operational model. |

## Contribution selection rule

A proposed feature is a good fit only when it improves a reviewer’s ability to understand **declared or pre-recorded local evidence** while preserving deterministic behavior, explicit limits, testability, privacy minimization, and no external side effects.
