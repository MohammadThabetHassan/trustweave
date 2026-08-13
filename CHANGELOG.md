# Changelog

All notable changes to TrustWeave are documented in this file. The project follows a keep-a-changelog style and uses semantic versioning for authorized releases.

## [Unreleased]

### Changed

- Added reviewer-facing `risk-review.md` output and active-risk-only SARIF export that retains a canonical local risk fingerprint while omitting currently baselined or suppressed entries.
- Added `risk-check`, a local deterministic risk-review command that normalizes supplied review artifacts into stable fingerprints and applies explicit expiry-enforced baselines and suppressions.
- Added severity gates for active local findings, safe empty baseline/suppression templates, and maintainer guidance that distinguishes reviewer documentation from remediation or runtime enforcement.

- Added optional declarative policy constraints for exact source data classifications and bounded tool-capability globs, so those declared security attributes now affect tested flow decisions.
- Added deterministic decision severities (`high`, `medium`, and `info`) with explicit policy overrides from the documented `critical` through `info` vocabulary.
- Made manifest, policy, scenario, trace, MCP profile, MCP inventory, and supported framework-declaration parsers reject unknown declared fields by default with path-aware close-match diagnostics.
- Added schema-and-runtime conformance tests for every checked-in manifest, policy, trace, and MCP profile fixture; the repository reality check now enforces the published-schema side in CI.
- Declared `jsonschema` as a development-only conformance dependency and recorded the typed-parser authority decision in ADR-0001.
- Made generated evidence builders pure: volatile `generated_at` provenance is now injected at the CLI boundary through an explicit timestamp, `SOURCE_DATE_EPOCH`, or the local UTC clock.
- Added `trustweave.dev/attestation/v1alpha2`, whose local integrity chain covers canonical stable bundle and test-result payloads rather than volatile generation metadata. The verifier remains compatible with local `v1alpha1` statements.
- Added stable CLI exit codes for invalid input/configuration, input/output failure, and unexpected internal errors; expected failures now write concise diagnostics to stderr, while `--debug` preserves tracebacks.
- Replaced repeated-list duplicate detection in the manifest, scenario, and MCP-profile validators with linear-time counting.
- Added atomic artifact replacement and precise errors for missing files, directories supplied as files, invalid UTF-8, and output failures.
- Added PEP 561 `py.typed` package data and an isolated-wheel regression test proving the installed marker is present.

### Documentation

- Added a reproducibility and integrity contract that distinguishes deterministic decisions, stable evidence payloads, byte-identical output, volatile provenance, and unsigned local file integrity.
- Rebuilt the README as a concise developer landing page with a verified installation path, first successful local review, artifact meanings, safety boundaries, documentation map, public contribution routes, and a source-controlled product mark.
- Moved advanced workflow detail behind task-focused documentation links so the landing page remains skimmable without reducing the published command and safety contract.
- Refreshed the product contract, roadmap, release guide, security policy, governance guide, contribution guide, and TestPyPI validation guide to distinguish completed `0.1.1` release evidence from deliberate future scope.
- Added `SUPPORT.md` to route installation questions, safe bug reports, bounded feature proposals, and private vulnerability reports without promising unstaffed services.
- Added an evidence-led maturity plan that distinguishes repository-controlled 9.5+ work from external proof that must not be fabricated.
- Added a focused mutation-testing record with its Linux-only scope, exact 108-of-108 killed-mutant result, re-run procedure, and explicit non-blocking limitation.
- Added a checked-in minimal LangGraph-style project layout, provenance note, and static-import walkthrough that demonstrate a reviewable project configuration without installing, importing, compiling, or executing LangGraph code.

### Quality

- Corrected the stale adversarial-scenario claim in `docs/QUALITY.md` from ten to the source-derived count of 25.
- Extended the deterministic repository reality check to verify the source-derived adversarial scenario count, mutation record, mutation configuration, and released quality-documentation contract.
- Added exact deterministic-engine assertions for matching/default rationales, UTC timestamps, and complete bundle fields; the initial scoped mutation analysis killed 108 of 108 generated engine mutants.
- Added positive and malformed-config regression coverage for the provenance-backed LangGraph-style declaration example.
- Pinned every third-party GitHub Action used by CI and OIDC publishing to a reviewed full commit SHA, with readable release labels retained in comments.
- Extended the repository reality checker to reject mutable workflow-action references and require the factual supply-chain evidence guide.

### Security

- Added a supply-chain evidence guide that documents implemented immutable action pins, least-privilege OIDC publishing, wheel reproducibility, SBOM generation, dependency review, and intentional non-claims about signing, attestations, or external certification.

### Governance

- Added structured public issue forms for reproducible bugs and bounded feature proposals, with explicit safeguards against publishing credentials, personal data, raw trace content, tool arguments, or third-party targets.
- Added issue-template routing, a transparent ownership map, and a public contribution path while preserving private vulnerability reporting and the non-executing core boundary.

## [0.1.1] - 2026-08-13

### Release

- Promoted the TestPyPI-validated `0.1.1rc2` package to the final `0.1.1` release target.
- Added a dedicated, manually dispatched production PyPI workflow that builds and validates distributions in an unprivileged job before an isolated GitHub OIDC trusted-publishing job uploads them.
- Added an import-version synchronization regression test to keep the installed `trustweave.__version__` value aligned with the package metadata.

### Security

- The production workflow grants `id-token: write` only to its isolated publishing job, uses no stored upload token, and disables package attestations pending separately authorized signing work.
- Production publication does not change repository visibility or the local-only, non-executing product boundary.

## [0.1.1rc2] - 2026-08-13

### Fixed

- The import-visible `trustweave.__version__` now matches the version declared in `pyproject.toml`.
- A regression test prevents package metadata and import-level version values from diverging in a future release candidate.

### Validation

- This candidate supersedes `0.1.1rc1` as the TestPyPI validation target after the clean-install check identified its immutable runtime-version mismatch.

## [0.1.1rc1] - 2026-08-13

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
- An optional `approval_control` policy declaration and `TW-POL-004` through `TW-POL-006` static review signals for missing approval documentation, incomplete action-context binding, and fail-open approval intent on sensitive/external approval-required paths.
- `trustweave policy-check --exit-on-review`, clear and deliberately review-required approval-policy fixtures, and hosted CI coverage for deterministic approval-boundary evidence.
- `trustweave sarif`, which deterministically converts selected existing policy, bundle-diff, trace, and MCP-profile review artifacts into a local SARIF 2.1.0 file with stable ordering and partial fingerprints.
- A cited ten-pattern synthetic adversarial scenario pack, additive scenario metadata, and `trustweave explain` for local policy-boundary education without prompts, payloads, model calls, or network access.
- `trustweave mcp-import`, a strict local normalizer for an already-provided MCP `tools/list` snapshot that creates a deterministic review inventory without server discovery, connection, authorization inference, or tool invocation.
- A release-blocking 90% branch-coverage gate, property-based fail-closed policy tests, Python 3.11/3.13 hosted compatibility jobs, fixed-epoch reproducible-wheel verification, and reproducible CycloneDX SBOM evidence.
- Corrected package URLs, governance review cadence, and a best-effort private security-report acknowledgement objective.
- SARIF unit coverage, CLI validation, repository-reality coverage, and hosted CI assertions for policy, diff, trace, and MCP review signals in the generated local evidence file.
- Strict manifest, policy, and scenario validation with explicit trust labels, action classes, and fail-closed behavior.
- A fully synthetic customer-support-agent example with deterministic allow, deny, and approval-required paths.
- Unit and end-to-end tests for validation, policy decisions, scenario results, evidence verification, source/tool/capability bundle diffs, static policy review, offline trace review, static MCP profile review, privacy omission, review-gate behavior, and the complete CLI workflow.
- Architecture, product-contract, threat-model, contribution, security, governance, and release documentation.
- GitHub workflows for quality checks, dependency review, Bandit static source-security scanning, package builds, isolated wheel verification, declared dependency auditing, policy review, candidate bundle-diff evidence, offline trace review, static MCP profile review, review-gate behavior, and report privacy assertions.
- An expanded 25-pattern cited synthetic adversarial scenario baseline, including MCP metadata drift, tool confusion, supply-chain provenance, delegated-agent, approval-boundary, and memory-boundary labels.
- A local MCP inventory-to-reviewer-required-manifest scaffold plus an explicit reviewer workflow that requires humans to declare sources, flows, capabilities, action classes, and policy.
- Static declaration inventories and non-executing proof walkthroughs for LangGraph, OpenAI Agents SDK, and CrewAI.
- An explicitly unsigned statement-shaped local evidence export; it preserves local digests without creating an external provenance or identity claim.
- A manual TestPyPI-only OIDC publishing workflow that separates distribution building from publishing and uses no stored upload token.

### Security

- The v0.1 core does not execute MCP configurations, agent tools, external commands from manifests, network requests, or model calls.
- The v0.1 attestation is locally hash-linked only; it is not a signed or transparency-log-backed attestation.
- The `0.1.1rc1` and `0.1.1rc2` TestPyPI workflow disables package attestations and does not publish to production PyPI, change repository visibility, or create a public release.
- Approval-control declarations are design-time evidence only; TrustWeave does not implement approval queues, authenticate approvers, or verify approval records at runtime.
- SARIF export is a local format conversion only; TrustWeave does not upload results, enable GitHub Code Security, or assert compatibility with a particular hosted code-scanning configuration.
- Scenario references and MCP tools-list metadata are local review inputs, not trusted authorization, exploit demonstrations, live-system observations, or evidence that a remote server behaves as declared.
- Fixed-epoch reproducibility is enforced for wheels only; compressed source-distribution reproducibility is not yet a release gate.

### Known limitations

- No MCP proxy, runtime enforcement, framework SDK, automatic discovery, external signature provider, or enterprise integration is included.
- JSON inputs work with no dependency. Safe YAML parsing requires the optional PyYAML dependency.
- Production publication uses the dedicated trusted-publishing workflow; external signing, hosted-result uploads, and runtime integrations remain separately authorized work.
