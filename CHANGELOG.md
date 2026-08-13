# Changelog

All notable changes to TrustWeave are documented in this file. The project follows a keep-a-changelog style and intends to use semantic versioning once a release is authorized.

## [Unreleased]

### Added

- A local CLI for scanning declared agent manifests, running synthetic policy tests, generating hash-linked evidence, rendering Markdown reports, and verifying internal evidence chains.
- Strict manifest, policy, and scenario validation with explicit trust labels, action classes, and fail-closed behavior.
- A fully synthetic customer-support-agent example with deterministic allow, deny, and approval-required paths.
- Unit and end-to-end tests for validation, policy decisions, scenario results, evidence verification, and the complete CLI workflow.
- Architecture, product-contract, threat-model, contribution, security, governance, and release documentation.
- GitHub workflows for quality checks, dependency review, and release-oriented evidence checks.

### Security

- The v0.1 core does not execute MCP configurations, agent tools, external commands from manifests, network requests, or model calls.
- The v0.1 attestation is locally hash-linked only; it is not a signed or transparency-log-backed attestation.

### Known limitations

- No MCP proxy, runtime enforcement, framework SDK, automatic discovery, external signature provider, or enterprise integration is included.
- JSON inputs work with no dependency. Safe YAML parsing requires the optional PyYAML dependency.
- The repository has not yet been published or released; release notes will be added only after hosted checks and explicit release authorization.
