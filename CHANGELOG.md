# Changelog

All notable changes to TrustWeave are documented in this file. The project follows a keep-a-changelog style and intends to use semantic versioning once a release is authorized.

## [Unreleased]

### Added

- A local CLI for scanning declared agent manifests, running synthetic policy tests, generating hash-linked evidence, rendering Markdown reports, and verifying internal evidence chains.
- `trustweave policy-check`, which creates static evidence for ordered-rule shadowing, permissive default decisions, and untrusted-input rules that allow sensitive or external actions.
- `trustweave diff`, which compares generated Agent Security Bundles and reports declared source, tool, path, matching-rule, and policy-decision changes.
- A safe baseline/candidate example that demonstrates review of a newly declared synthetic external capability without executing a tool, plus a capability-growth candidate for least-privilege review of an existing sensitive tool.
- A machine-readable policy schema and an operational quality-evidence guide.
- `trustweave trace-review`, an offline local-trace review that compares minimized tool-call metadata with declared sources, tools, flows, and deterministic policy.
- A machine-readable trace schema, clear and review-required synthetic trace fixtures, and privacy-preserving JSON/Markdown trace-review artifacts.
- Task-oriented CLI, trace-review, MCP-profile, schema-compatibility, and roadmap documentation, plus an ecosystem-research record that explains the project’s deliberate non-runtime boundary.
- `trustweave mcp-profile-check`, a static local MCP metadata profile review that validates identifier hygiene and tool-to-manifest mapping without server discovery, transport access, OAuth, token handling, or tool execution.
- A machine-readable MCP profile schema, clear and review-required profile fixtures, minimized profile-review reports, and CI gate coverage.
- Capability-level bundle diff evidence that records added and removed declared capabilities for existing tools and emits `TW-DIFF-003` when a sensitive or external tool grows its declared scope.
- A deterministic repository reality checker that validates local Markdown links, JSON schemas, workflow YAML, and documented CLI commands; hosted CI now gates on it.
- Strict manifest, policy, and scenario validation with explicit trust labels, action classes, and fail-closed behavior.
- A fully synthetic customer-support-agent example with deterministic allow, deny, and approval-required paths.
- Unit and end-to-end tests for validation, policy decisions, scenario results, evidence verification, source/tool/capability bundle diffs, static policy review, offline trace review, static MCP profile review, privacy omission, review-gate behavior, and the complete CLI workflow.
- Architecture, product-contract, threat-model, contribution, security, governance, and release documentation.
- GitHub workflows for quality checks, dependency review, Bandit static source-security scanning, package builds, isolated wheel verification, declared dependency auditing, policy review, candidate bundle-diff evidence, offline trace review, static MCP profile review, review-gate behavior, and report privacy assertions.

### Security

- The v0.1 core does not execute MCP configurations, agent tools, external commands from manifests, network requests, or model calls.
- The v0.1 attestation is locally hash-linked only; it is not a signed or transparency-log-backed attestation.

### Known limitations

- No MCP proxy, runtime enforcement, framework SDK, automatic discovery, external signature provider, or enterprise integration is included.
- JSON inputs work with no dependency. Safe YAML parsing requires the optional PyYAML dependency.
- The repository has not yet been published or released; release notes will be added only after hosted checks and explicit release authorization.
