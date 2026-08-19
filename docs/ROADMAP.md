# TrustWeave Roadmap

## Product direction

TrustWeave is a **local evidence layer for AI-agent trust-boundary review**. It makes declared architecture, deterministic policy outcomes, synthetic regression results, and pre-recorded local metadata visible before a configuration change reaches production. It must not become an unrestricted agent runner, MCP proxy, exploit tool, credential scanner, model evaluator, or live infrastructure scanner.

The roadmap favors improvements that make an existing reviewer decision more reproducible and understandable. A feature is not a fit merely because it is common in an agent platform; it must preserve deterministic behavior, local inputs, privacy minimization, explicit limits, and no hidden external side effects.

## Completed foundation

| Capability | Status | Evidence |
| --- | --- | --- |
| Declared source, tool, capability, and flow inventory | Complete | Strict manifest validation and Agent Security Bundle generation. |
| Deterministic flow-policy evaluation | Complete | First-match policies, synthetic scenarios, and static policy review. |
| Configuration change review | Complete | Bundle diffs with source, tool, capability, path, rule, and decision signals. |
| Local integrity evidence | Complete | Hash-linked local attestation, verifier, and explicitly unsigned statement export. |
| Offline observed-evidence review | Complete | Local trace-policy review with privacy-preserving reports and an explicit review gate. |
| Static MCP metadata review | Complete | Local profile-to-manifest mapping with strict transport and authorization-expectation checks; no connection. |
| Static MCP tools-list inventory | Complete | Normalization of an already-provided `tools/list` snapshot; no discovery, connection, or action-class inference. |
| Framework declaration normalization | Complete | Static proof fixtures for LangGraph, OpenAI Agents SDK, and CrewAI; no SDK import or execution. |
| Cited synthetic adversarial scenarios | Complete | Twenty-five OWASP-, MITRE-, and MCP-shaped label-only scenarios with deterministic expectations. |
| Interoperable review export | Complete | Deterministic local SARIF 2.1.0 generation with no automatic upload. |
| Quality automation | Complete | 95% branch coverage, property-based fail-closed tests, formatting, linting, type checks, static source scanning, isolated package checks, wheel reproducibility, SBOM, dependency audit, cross-platform compatibility jobs, and a twelve-module mutation gate. The gate enforces a ≥95% score together with exact survivor-identifier and normalized-diff parity, zero untriaged records, and zero `needs_regression` classifications on the reviewed SHA. |
| Package release path | Prepared | Production PyPI `0.1.1` is published. Corrected source target `0.2.1` remains owner-authorized; `v0.2.0` is an immutable unpublished audit tag that must not be reused or published from. |
| Governance baseline | Complete | Pull-request review, an owner-controlled release procedure, contribution guidance, and a private security-report route. |

## Current priorities

### 1. Contract maturity and reviewer feedback

The first post-release priority is to collect feedback from maintainers and reviewers using the documented local workflows. Useful evidence includes whether the manifest and policy vocabulary is understandable, whether review signals are actionable, and whether the generated Markdown artifacts support an actual change-review decision. Feedback should be documented as issues or examples without publishing customer data, credentials, trace content, or third-party targets.

Input schemas retain their documented v1alpha1/v1alpha2 contracts. Current generated bundle, bundle-diff, and risk-review artifacts use explicit v1alpha2 versions while bounded historical v1alpha1 resources remain packaged. A future stabilization decision requires a written compatibility policy, representative migration evidence, and a clear statement of which artifact fields and review identifiers become stable.

### 2. Curated file-only declaration importers

TrustWeave can add narrowly scoped importers for carefully selected framework declaration formats when each importer accepts an already-provided local file, validates it strictly, preserves source provenance and limits, and never executes a framework, discovers an endpoint, accesses credentials, or infers authorization. Each importer must include positive, negative, and boundary fixtures.

### 3. Optional review-platform adapters

A future adapter may render an existing local artifact as a pull-request-friendly summary or an explicit export file. Any service posting, repository annotation, or code-scanning upload must remain opt-in, use least-privilege permissions, preserve the privacy boundary, and receive separate maintainer authorization. The core must remain fully useful without the adapter.

### 4. Authenticated provenance design

TrustWeave currently produces local hash-linked evidence and explicitly unsigned statement-shaped exports. Adding DSSE, Sigstore, SLSA, or transparency-log support would require a separate design that defines identity, key custody, signing scope, verification procedure, publication behavior, failures, retention, and how reviewers distinguish local integrity from authenticated provenance.

## Maintainer decisions that require explicit authorization

| Decision | Why it needs a maintainer decision beyond a code change |
| --- | --- |
| Publish a new PyPI version | Distribution is permanent, versioned public release activity and must use the documented OIDC release path. |
| Add a hosted integration or automatic result upload | It can create external effects, permissions, retention obligations, and privacy risk. |
| Sign artifacts or publish provenance | It creates identity and verification commitments that must be documented and maintained. |
| Add runtime interception, live discovery, or remote analysis | It crosses the local, non-executing safety boundary and requires a different operational threat model. |
| Apply for an external assessment, badge, sponsorship, or certification | It requires external assertions and ongoing maintainer commitments. |

## Explicitly deferred work

| Capability | Why it is deferred |
| --- | --- |
| Runtime tool interception | It belongs to an authorization and enforcement layer with identity, availability, rollback, and incident-response requirements. |
| Live agent or MCP execution | It crosses the non-executing safety boundary and would require isolated environments, credential policy, and explicit authorization. |
| Prompt-injection classification from raw text | It risks false confidence, privacy exposure, and model-dependent behavior outside the deterministic core. |
| Automatic vulnerability scanning of third-party skills | It requires a dedicated analysis engine, malicious-input handling, licensing review, and a different threat model. |
| Source-distribution byte reproducibility | Fixed-epoch wheel reproducibility is implemented; compressed-sdist determinism requires a separate packaging design. |
| Multi-tenant service or hosted dashboard | It requires a complete privacy, authentication, authorization, data-retention, availability, and operational model. |

## Contribution selection rule

A proposed feature is a good fit only when it improves a reviewer’s ability to understand **declared or pre-recorded local evidence** while preserving deterministic behavior, explicit limits, testability, privacy minimization, and no external side effects. See [CONTRIBUTING.md](../CONTRIBUTING.md), [the product contract](PRODUCT_CONTRACT.md), and [the threat model](THREAT_MODEL.md) before proposing scope expansion.
