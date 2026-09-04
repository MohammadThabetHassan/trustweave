# Changelog

All notable changes to TrustWeave are documented in this file. The project follows a keep-a-changelog style and uses semantic versioning for authorized releases.

## [0.3.1] - Unreleased release candidate

### Added

- `trustweave discover` statically analyzes local Python source for the tool surface an
  agent can reach, proposes an action class per tool from a versioned symbol catalog with
  the evidence that produced it, reports declaration drift in both directions against a
  supplied manifest, and emits a declaration-coverage figure. Trust is always emitted as
  `unknown`; the analyzer never infers it. Recorded in ADR-0006, which narrows the
  previously published boundary on repository analysis.
- `trustweave.dev/code-discovery/v1alpha1` artifact contract and schema.
- Ten `TW-CODE-*` review rules covering refusal, drift, and declaration mismatch.
- `discover` recognises the registration forms agents actually use: Semantic Kernel plugin
  methods, LangChain `BaseTool` subclasses whose behaviour sits in `_run` or `_arun`, and
  the names a low-level MCP server declares in `list_tools` and implements in one
  `call_tool` handler. Every tool in the classification benchmark is now discovered.
- Tools whose registered name differs from the function that implements them record both.
  A factory can expose `object_summary` while the code that runs is
  `summarize_bucket_object`; the artifact carries an `implementation` field and the report
  prints it under the registered name.
- `docs/classifier-evaluation-v1.json` records the benchmark result, broken down by
  registration form and refusal reason, and a ratchet in the test suite holds accuracy,
  precision when answering, tools discovered, and per-class recall against it.

### Added

- Added versioned evaluation governance, a deterministic twelve-case synthetic corpus, local preflight validation, corpus lifecycle controls, reviewer quickstart, archive-readiness materials, and safe public-feedback/triage infrastructure. These are prepared repository-controlled foundations; no independent reviewer, pilot, adoption, benchmark, archive, or security-efficacy result is claimed.
- Added an owner-facing GitHub governance decision record, a manually triggered least-privilege OpenSSF Scorecard assessment workflow that retains a local GitHub Actions artifact without publishing results, and a record template that prohibits score, badge, certification, or remediation claims before owner-reviewed evidence exists.
- Added a fixed offline reviewer packet, consent-aware feedback and result-record templates, and a deterministic local artifact builder/verifier that allowlists public-safe files, records SHA-256 digests, rejects unsafe paths and credential-like content, and creates deterministic local ZIP packages without upload or network behavior.

### Fixed

- Effects that were reachable but unreported, each of which had the analyzer describe a
  tool as harmless when it was not: a symbol called through a local alias, a method on an
  instance the tool constructs, a sibling method reached through `self`, a client used
  behind an attribute chain, a receiver handed to a helper, a credential path assembled by
  `/` composition, and a literal argument the deciding call sees one frame up. Constructing
  the object a protocol requires a tool to return no longer suppresses an observed effect.
- An observed effect at the top of the precedence order is reported even when something
  else in the same tool could not be resolved, since nothing outranks it. Below that class
  the refusal stands.

### Changed

- Separated the prepared source version from the last observed public package release in the compatibility contract so an unreleased candidate cannot be presented as published provenance evidence.
- Replaced fragile README release-version prose with durable PyPI and GitHub Releases references while retaining the exact historical `0.3.0` release-evidence limit.
- Rewrote the README around a verified two-minute quickstart with real output, a curated docs index, and a shorter plain-language explanation of the evidence-not-enforcement boundary.
- Reorganized documentation: point-in-time release checklists, migration guides, audit records, and the maintainer handoff snapshot moved to `docs/archive/` with an index; ADRs moved to `docs/adr/`; the documentation site navigation is grouped by task (getting started, concepts, how-to, CLI, policies, assurance, releases).
- Tightened the installation and troubleshooting pages, fixed stray code-block indentation, and made the missing-paths configuration error list exactly which paths it wants.

### Release status

- Source metadata is prepared as `0.3.1`, but **`0.3.1` is not published, tagged, uploaded, or released**. The latest observed public package release remains `0.3.0` until a separately owner-authorized publication process completes and records new exact-file evidence.

## [0.3.0] - 2026-08-20

### Fixed

- Enforced semantic authenticity and complete finding coverage for current Agent Security Bundles by regenerating the expected findings from the embedded manifest and policy during validation.
- Corrected policy coverage analysis so an impossible earlier rule cannot shadow a possible later rule, and aligned typed-policy collection and text bounds with the published v1alpha2 schema.
- Introduced `trustweave.dev/bundle-diff/v1alpha3`, which records normalized policy-only changes and review signals for fail-closed-to-fail-open approval controls (`TW-DIFF-004`), default-to-allow changes (`TW-DIFF-005`), approval-control removal (`TW-DIFF-006`), approval-binding removal (`TW-DIFF-007`), less-restrictive rule decisions (`TW-DIFF-008`), required-control removal (`TW-DIFF-009`), classification-taxonomy changes (`TW-DIFF-010`), and structural rule-set or matching-boundary changes requiring human review (`TW-DIFF-011`). The structural signal does not prove that every reported change is insecure or that every possible weakening is detected.
- Repaired the risk-management quickstart with current v1alpha2 baseline and suppression examples, plus a clean-workspace command smoke regression.
- Bound TestPyPI and PyPI publication workflows to an exact annotated `v<version>` tag and immutable target SHA. Before artifact build or isolated trusted publication, the release-gate job executes exactly: formatting and lint checks, strict typing, Bandit, pytest, `reality_check`, strict documentation build, and dependency audit. CodeQL, dependency review, mutation testing, cross-Python compatibility, build reproducibility, and isolated-wheel smoke remain separate CI or release-process controls and are not claimed as release-gate steps.
- Replaced overstated local “tamper-evident” wording with explicit unsigned-statement and external-provenance limits, and made supplied-file verification the primary documented verification command.
- Replaced the Docker image’s stale hard-coded version label with a package-metadata-derived build argument that hosted CI verifies against the installed package version.
- Made `python scripts/verify_audit_remediation.py` execute an exact, fail-closed `TW-AUDIT-001` through `TW-AUDIT-010` pytest-node mapping alongside separate corrective hardening evidence, rather than relying on a broad file-only test list.

### Changed

- Regenerated deterministic golden evidence, mutation-contract snapshots, rule catalog, compatibility contracts, traceability records, and repository-reality checks for the current v1alpha3 diff output.

> Published `0.2.3` emits `trustweave.dev/bundle-diff/v1alpha2`; `0.3.0` introduces the reviewed `v1alpha3` writer. The annotated [`v0.3.0`](https://github.com/MohammadThabetHassan/trustweave/tree/v0.3.0) tag, exact-SHA release gates, TestPyPI and PyPI trusted publication, exact-file expected-repository verification, clean installations, and [GitHub Release](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.3.0) completed successfully. See [Release Evidence 0.3.0](docs/RELEASE_EVIDENCE_0.3.0.md). The non-executing, local-only product boundary remains unchanged.

## [0.2.3] - 2026-08-19

### Added

- Added a versioned machine-readable compatibility contract, public support/deprecation policy, and deterministic validator for the package version, Python matrix, CLI surface, exit statuses, current artifact writers, and bounded historical readers.
- Added a reviewed synthetic golden evidence corpus covering complete staged CI, three framework descriptors, saved MCP metadata/profile review, trace/risk lifecycle review, declared change/SARIF review, and malformed-input refusal. The default verifier compares approved canonical digests and never refreshes snapshots implicitly.
- Added a generated threat-control-test traceability guide and source contract linking every declaration-layer threat-model row and out-of-scope risk to real source, tests, evidence, maintenance triggers, or explicit residual limits.
- Added explicit local resource-bound documentation and a fail-closed **50,000 unique-result** SARIF cardinality limit, alongside existing input-file, structural, and declared-chain budgets.
- Added temporary clean-environment distribution assurance that builds, archive-checks, and installs both the wheel and source distribution with console, module-entry, and packaged-schema checks.
- Added TestPyPI-first package-provenance controls: both trusted-publishing workflows request PyPI project attestations, and a versioned validator requires the configuration while preserving the pre-observation non-claim.

### Changed

- Extended the repository reality gate and hosted CI with golden-evidence, traceability, distribution-assurance, compatibility, and package-provenance control checks.
- Expanded the README and documentation site with task-oriented assurance navigation and release guidance that distinguishes configured attestation generation from observed authenticated package provenance.
- Bumped source metadata to `0.2.3`; published-state documentation and compatibility records now identify `0.2.3` as the current public package release.

### Release status

- `0.2.3` is published on [PyPI](https://pypi.org/project/trustweave/0.2.3/), [TestPyPI](https://test.pypi.org/project/trustweave/0.2.3/), and [GitHub Release `v0.2.3`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.3). Its exact TestPyPI and PyPI wheels passed clean-install and expected-repository provenance verification; see [the release evidence record](docs/archive/RELEASE_EVIDENCE_0.2.3.md).
- `0.2.2` remains available as the preceding public release. The non-executing, local-only boundary remains unchanged.

## [0.2.2] - 2026-08-19

### Added

- Added `python -m trustweave` as a standard module entry point alongside the installed `trustweave` console command, with source-checkout and installed-wheel regression coverage for matching version and help behavior.
- Added a task-oriented developer integration-routes page with copy-paste local examples for LangGraph-style declarations, exported OpenAI Agents descriptors, saved MCP `tools/list` snapshots, and repository CI inputs.

### Changed

- Made the README and documentation-site installation path expose both supported CLI invocations, route developers by the local input they already have, and link directly to framework, MCP, and least-privilege CI guidance.
- Updated the checked-in CI integration example to the currently reviewed immutable `actions/checkout` v7.0.1 pin.
- Extended the repository reality check to validate module-style help from an isolated installed wheel and to reject the prior stale README release wording.

### Release status

- `0.2.2` is published on [PyPI](https://pypi.org/project/trustweave/0.2.2/), validated from [TestPyPI](https://test.pypi.org/project/trustweave/0.2.2/) and PyPI clean installations, and available as [GitHub Release `v0.2.2`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.2). Its annotated tag targets `3b0817e732627a62a18be82e854a58fa085f0922`. It does not change the non-executing, local-only product boundary.

## [0.2.1] - 2026-08-19

> This corrected public release was authorized and published from annotated tag [`v0.2.1`](https://github.com/MohammadThabetHassan/trustweave/tree/v0.2.1), which targets `f1394d5fba8a0fbc24e3a18f45702e83aa65645e`. The protected trusted-publishing workflows completed successfully, and the exact package was validated from both TestPyPI and PyPI.

### Fixed

- Added top-level `trustweave --version` and `trustweave -V` commands. Both print only the authoritative import-visible package version, exit successfully without a subcommand, and do not discover configuration, write files, or access the network.
- Added source-checkout and installed-wheel regression coverage for the version contract, including exact stdout, empty stderr, package-metadata synchronization, and installed console-script behavior.
- Corrected the release procedure after the immutable `v0.2.0` pre-publication tag exposed the missing top-level version smoke command. The corrected clean-checkout staged-CI reproducibility procedure remains required and does not depend on a tracked root `trustweave.toml`.

### Release status

- `v0.2.0` targets `7232fe3a23d92f50a693903c0a6b7cb92d0a1426` and remains an immutable **unpublished audit record**. It was never published to PyPI and has no GitHub Release; it must not be moved, reused, or published from.
- `0.2.1` is published on [PyPI](https://pypi.org/project/trustweave/0.2.1/), validated on [TestPyPI](https://test.pypi.org/project/trustweave/0.2.1/), and available as [GitHub Release `v0.2.1`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.1). See [the 0.2.1 release notes](docs/archive/RELEASE_NOTES_0.2.1.md) and [completed owner release record](docs/archive/OWNER_RELEASE_CHECKLIST_0.2.1.md).

## [0.2.0] - Unpublished immutable audit record

> `v0.2.0` was created during pre-publication verification and intentionally remains unpublished. No PyPI file and no GitHub Release was created for it. The tag is retained unchanged for auditability; `0.2.1` is the corrected release target.


### Fixed

- Added strict semantic validation for historical `agent-security-bundle/v1alpha1` evidence while preserving explicitly documented safe compatibility behavior for authentic v0.1.1 local bundles. Current v1alpha2 bundle validation remains strict.
- Enforced the exact risk-decision expiry boundary: a baseline or suppression expiring at the local review timestamp is expired rather than active.
- Hardened strict risk, SARIF, chain, attestation, canonical-finding, policy, configuration, and staged-CI contracts with malformed-input, field-path, lifecycle, ordering, and provenance regressions.
- Enforced strict declared-chain node roles, removed the ambiguous `output` node kind, and applied path, state, and edge budgets before retaining limit-plus-one work in partial local analysis.
- Preserved ordered declared chain paths in risk fingerprints and deeply froze normalized risk subjects, preventing a mutable caller or a reversed path from inheriting another local decision identity.
- Unified built-in review observations behind a bounded, deeply immutable canonical finding contract. Ordered chain paths, safe integer analysis metadata, producer conformance, and published finding-schema validation now agree without permitting arbitrary nested evidence.

### Changed

- Split the command-line implementation into focused command modules behind a sub-200-line public facade, preserving stable command help and exit-code behavior with golden help contracts.
- Made the repository reality check validate real generated artifacts, exact schema resources from an installed wheel, and CLI command coverage derived from the authoritative parser.
- Centralized built-in review-rule guidance for producer validation, SARIF rule metadata, Markdown review reports, generated rule-catalog documentation, and reality-check completeness enforcement.
- Deduplicated raw review and derived risk-review SARIF results by canonical finding fingerprint while preserving every contributing local artifact location.
- Made `LocalReviewResult` recursively immutable and defensively copied so nested caller-owned review data cannot mutate public API results.
- Rejected risk baseline drafts whose expiry is not later than the supplied local review timestamp.
- Rejected unknown policy-v2 required controls outside the bounded declared-control catalog and rejected rules with an empty exact-classification and taxonomy-bound intersection.
- Preserved every distinct declared chain path during bounded traversal and scoped fail-closed approval evidence to sensitive classifications acquired before the approval node.
- Aligned generated bundle, embedded finding, and v1alpha3 attestation schemas with real runtime artifacts, and packaged public schemas for installed-wheel discovery.
- Added the immutable, data-only `trustweave.api.LocalReviewResult` wrapper for typed consumption of already-generated local review artifacts.
- Expanded `trustweave ci` into a staged local coordinator with strict typed configuration, bounded configuration discovery, selectable core review stages, atomic artifact-directory publication, deterministic summaries, `--format`, `--quiet`, `--fail-on`, optional declared-chain review, and local SARIF generation. No stage executes agents, models, tools, MCP servers, or network operations.
- Added explicit local `trustweave baseline create`, `baseline validate`, and `suppressions validate` lifecycle commands. Baseline creation requires a reviewer-provided reason and expiry and never claims remediation or authorization.
- Added strict read-only `trustweave config validate` and `config show` commands plus explicit or bounded auto-discovered `trustweave.toml` path resolution for `scan`, `test`, `policy-check`, and staged `ci` execution.
- Added opt-in `trustweave policy-check --coverage` diagnostics for first-match reachability, contradictory shadowed decisions, and impossible declared control requirements, with the same local deterministic policy boundary.
- Made declared-chain analysis stateful for propagated sensitive classifications and fail-closed approval state, and added explicit edge, depth, and state budgets to prevent unbounded local review work.
- Made flow `purpose_tags` an additive, validated manifest attribute and aligned policy-v2 matching to these machine-readable identifiers rather than the human-readable `purpose` prose, while preserving v1alpha1 manifests without tags.
- Expanded `trustweave why` with deterministic per-dimension local match evidence for every evaluated policy rule, including unbounded dimensions and declared-control checks.
- Added deterministic orphaned baseline and suppression reporting to local risk reviews so stale decisions remain visible without altering the active-finding gate or claiming remediation.
- Restored the owner-enabled SHA-pinned GitHub dependency-review action for pull-request dependency changes while retaining the independent `pip-audit` audit.
- Added a versioned bounded `trustweave.dev/policy/v1alpha2` contract with optional declared source/tool identifiers, purpose tags, classification bounds, and required declared controls, plus machine-readable `trustweave why` explanations.
- Added `trustweave chain-check` for bounded static review of explicitly supplied chain graphs and local chain-review integration with risk normalization and SARIF conversion. It reports declarations only and does not infer runtime paths.
- Added the typed, data-only `trustweave.api` public surface and repository-local composite-action, pre-commit, GitLab, and Jenkins integration assets with no default uploads or automation against external systems.

- Added an additive `trustweave.dev/finding/v1alpha1` contract for canonical local policy-review and bundle-diff entries. Stable evidence kinds and declared subjects support wording-independent local correlation while retaining existing review fields and the non-executing privacy boundary.
- Added `trustweave.dev/attestation/v1alpha3`, which binds stable payload hashes, exact file hashes, subject names, and source revision. `verify --bundle --test-results` now checks supplied local evidence bytes; readers retain `v1alpha1` and `v1alpha2` compatibility.
- Made `risk-check` schema-aware for policy, trace, MCP-profile, and bundle-diff review evidence. It now normalizes documented `findings` and diff `signals` into semantic `trustweave/fingerprint/v3` identities, preserves local input paths, and deterministically deduplicates exact identities.
- Restricted policy capability matching to exact capabilities or one final namespace wildcard, made shadow analysis conservative across classification and capability constraints, and made optional scenario attributes use the same deterministic matcher as declared manifest flows.
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

### Documentation

- Added a strict-build MkDocs Material documentation site with local-boundary concepts, generated parser-derived CLI help, a built-in review-rule catalog, schema catalog, and deferred authenticated-provenance design guidance.
- Added deterministic documentation freshness and strict site-build checks to the repository reality checker.

### Quality

- Completed a twelve-module mutmut measurement with **6,044 of 6,140 mutants killed (98.44%)**. The regenerated 96-survivor inventory preserves exact normalized source diffs and records **zero untriaged** and **zero `needs_regression`** entries, with code-level equivalence proofs retained for every surviving mutation. The hosted mutation workflow enforces exact survivor-identifier and normalized-diff parity on the reviewed SHA.
- Strengthened the hosted mutation workflow to require a 95% score, internally consistent evidence, exact survivor-identifier parity, exact normalized survivor-diff/triage parity, non-empty equivalent/defensive rationales, zero untriaged records, and zero `needs_regression` classifications.
- Raised the enforced branch-coverage gate to 95% after expanding deterministic boundary and property-based regression coverage for local configuration, public review envelopes, manifests, policies, chains, traces, MCP profiles, risk lifecycle decisions, bundle diffs, CLI error handling, and unsigned statements.

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
