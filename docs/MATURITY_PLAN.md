# TrustWeave Maturity Plan

## Purpose

This plan defines how TrustWeave can credibly advance from a strong early public release to **9.5+ open-source readiness** without expanding beyond its local, deterministic, non-executing product contract. It is an evidence plan, not a feature wish list: a completed item requires a versioned implementation, a testable control, or an explicit documented limitation.

> **Rating discipline.** A 9.5 rating means the primary workflow, documentation, governance, public presentation, and release evidence reinforce one another. A 9.9 rating additionally requires independent adoption or review evidence that cannot be manufactured by repository changes alone. Neither rating means that TrustWeave proves agent systems secure.

## Verified baseline

| Area | Present evidence | Residual limit |
| --- | --- | --- |
| Core reviewer workflow | Local manifest/policy scan, synthetic scenarios, diff, policy review, trace metadata review, MCP metadata review, SARIF conversion, and unsigned statement export. | Evidence describes supplied local declarations and metadata; it does not establish runtime behavior or enforcement. |
| Quality engineering | Strict type checking, formatting, linting, Bandit, property-based tests, 90% branch coverage, isolated wheel checks, wheel reproducibility, SBOM generation, dependency audit, and cross-platform Python 3.11/3.13 tests. | The project has not yet recorded focused mutation-analysis evidence. |
| Distribution | TestPyPI rehearsal, trusted publishing, production PyPI `0.1.1`, annotated tag, GitHub release, and fresh-install validation. | Package attestations and authenticated provenance are not yet enabled. |
| Public project baseline | Public repository, Apache-2.0 license, contribution/security/support routes, issue forms, private vulnerability reporting, release documentation, and 100% GitHub community-profile health. | The project has no independent contributors, issues, user feedback, or adoption evidence yet. |
| Framework coverage | Static adapters and fixtures for LangGraph, OpenAI Agents SDK, and CrewAI. | Current fixtures demonstrate supported declaration shapes, not provenance from a checked-in minimal framework project or runtime execution. |

## Confirmed integrity gaps

The following gaps are already confirmed and must be fixed before expanding the public claim surface.

| Priority | Gap | Why it matters | Required correction | Evidence of completion |
| --- | --- | --- | --- | --- |
| P0 | `docs/QUALITY.md` says the cited adversarial library has ten patterns; the tracked JSON library has 25. | A stale quality claim conflicts with the project’s evidence-first positioning. | State 25 precisely and add a deterministic consistency check that derives the documented count from the tracked scenario file. | Local and hosted reality checks fail if the count diverges. |
| P0 | Mutation-testing status is absent from `QUALITY.md`, the roadmap, and changelog. | An unrecorded quality limitation is more harmful than a bounded, explained limitation. | Run a focused Linux-only mutation audit of selected deterministic decision code, record the exact tool, scope, result, and platform limitation; if unresolved mutants remain, describe them without minimizing them. | Committed mutation report and a documented re-run procedure. |
| P1 | Third-party GitHub Actions are version-tagged rather than pinned to immutable full commit SHAs. | Mutable action tags weaken reproducibility and are a known supply-chain hardening gap. | Pin all third-party workflow actions to reviewed full SHAs and preserve readable version comments. | Workflow review and automated update path validate every pin. |
| P1 | Repository-native secret scanning, push protection, Dependabot security updates, and CodeQL are not currently enabled. | Public-repository security controls are discoverable maturity gaps, even though Bandit and dependency review already exist. | Enable only eligible controls; add code scanning and dependency-update configuration with least privilege and documented review boundaries. | GitHub Security tab and exact workflow runs demonstrate the controls. |
| P1 | Framework proof is fixture-based. | The adapters are useful but a skeptical evaluator cannot see how one representative declaration came from a framework-style project layout. | Add one minimal, checked-in LangGraph declaration project with a provenance note tied to current official configuration documentation. Do not import LangGraph or execute any graph. | Adapter output test, local walkthrough, source links, and explicit no-execution assertion. |

## The 9.5 release sequence

### Milestone 1 — Repair the evidence contract

Correct the scenario-count discrepancy, add mutation-analysis transparency, and extend the repository-reality checker so these facts cannot silently drift. This milestone is required because a security-evidence project must correct its own evidence drift before it asks users to trust more controls.

**Exit gate:** documentation count matches the source file; mutation scope and results are reproducible; all current quality checks remain green.

### Milestone 2 — Prove one framework boundary end to end

Add a minimal LangGraph-style declaration layout that is checked in as non-executing source material. The example should contain only safe symbolic graph labels and no environment values, prompts, tools, credentials, endpoints, model references, or executable imports. The documentation must explain exactly which local file is consumed, which fields are normalized, what is intentionally ignored, and why no framework code is run.

**Exit gate:** a positive fixture, malformed fixture, and boundary fixture are tested; the walkthrough is linked from the adapter guide; a reviewer can reproduce the inventory with one command.

### Milestone 3 — Strengthen maintainer and supply-chain evidence

Pin GitHub Actions to full reviewed SHAs, introduce a dependency update mechanism that opens reviewable pull requests rather than merging changes, enable secret scanning and push protection when eligible, and add CodeQL for Python and Actions with the smallest correct permissions. Do not claim a badge, SLSA level, signed release, or verified provenance until the project has actually completed the relevant external process.

**Exit gate:** no mutable third-party action references remain; the public security configuration is verifiable; code-scanning artifacts are produced; dependency updates remain reviewable and never auto-merge.

### Milestone 4 — Release only if package-relevant work exists

If the completed improvements modify distributed package behavior, package metadata, or released user-facing quality guarantees, prepare a patch release candidate such as `0.1.2rc1`. If the work is documentation and repository governance only, retain `0.1.1` as the package version and create no PyPI release merely to appear active.

**Exit gate:** the exact release commit has local and hosted green evidence; version, changelog, release notes, and package runtime version agree; the owner explicitly authorizes production publication immediately before the immutable tag is pushed.

## What a 9.9 claim would still require

Repository changes alone cannot create these signals. They must arise from real public interaction and must be described conservatively.

| Missing external proof | Responsible path | Never fabricate |
| --- | --- | --- |
| Independent reviewer feedback | Invite review of synthetic examples and record resolved, non-sensitive feedback in public issues or release notes. | Testimonials, stars, “users,” or adoption metrics. |
| External maintainer resilience | Add a second real maintainer only with that person’s consent and documented responsibilities. | Placeholder maintainers or nominal reviewers. |
| External security posture | Complete an OpenSSF Best Practices entry or other assessment only after meeting its criteria and accepting its maintenance obligations. | Badges, certifications, SLSA levels, or Scorecard outcomes not actually issued. |
| Authenticated provenance | Design and operate signing identity, scope, verification, failure handling, and retention with explicit owner authorization. | “Signed,” “attested,” or “tamper-proof” claims based only on local hashes. |

## Non-negotiable boundaries

The maturity plan must not make TrustWeave execute tools, call models, connect to MCP servers, access credentials, inspect third-party systems, scan live infrastructure, upload results, auto-merge updates, or claim runtime security. A rejected scope expansion is a successful outcome when it preserves the product contract.

## References

[1]: https://openssf.org/projects/best-practices-badge/ "OpenSSF Best Practices Badge Program"
[2]: https://scorecard.dev/ "OpenSSF Scorecard"
[3]: https://docs.github.com/en/code-security/how-tos/secure-your-secrets/detect-secret-leaks/enable-secret-scanning "GitHub Docs: Enabling secret scanning"
[4]: https://docs.github.com/en/code-security/how-tos/secure-your-secrets/prevent-future-leaks/enable-push-protection "GitHub Docs: Enabling push protection"
[5]: https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates "GitHub Docs: Dependabot security updates"
[6]: https://docs.github.com/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql "GitHub Docs: CodeQL code scanning"
[7]: https://mutmut.readthedocs.io/ "mutmut documentation"
[8]: https://docs.langchain.com/oss/python/langgraph/application-structure "LangGraph application structure"
