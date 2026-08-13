# Quality Evidence Guide

## Purpose

TrustWeave makes security-related review claims only when they are linked to reproducible artifacts. This guide defines the checks that maintainers must execute before a direct commit to `main` and before a release.

## Local verification

Run the following commands from a clean checkout. The package requires Python 3.11 or later; the repository CI currently verifies Python 3.12.

```bash
python -m pip install -e . bandit build pip-audit pytest ruff mypy PyYAML

ruff format --check .
ruff check .
mypy src
bandit -r src/trustweave -q
pytest
python -m build
pip-audit -r requirements.txt
```

The declared core runtime dependency set is intentionally empty in v0.1. Optional YAML parsing and developer tools are declared as package extras. An audit that reports no declared runtime packages is therefore expected and must not be described as an audit of the entire developer workstation.

## Required evidence workflows

| Workflow | Command | Expected evidence |
|---|---|---|
| Core bundle | `trustweave scan` | A validated `agent-security-bundle.json` with explicit flow decisions and limits. |
| Synthetic regression | `trustweave test` | Passing `security-test-results.json` for the versioned scenario pack. |
| Local integrity | `trustweave attest` then `trustweave verify` | An internally consistent hash-linked attestation. |
| Policy structure | `trustweave policy-check --exit-on-review` | A clear default-policy review with a documented, bound, fail-closed approval boundary, or an explicit non-zero review gate. |
| Change review | `trustweave diff` | Bundle-diff JSON and Markdown for baseline/candidate and capability-growth pairs. |
| Repository reality | `python scripts/reality_check.py` | Verified local Markdown links, JSON schemas, workflow YAML, and documented CLI commands. |
| Observed-evidence review | `trustweave trace-review` | Clear and review-required local trace artifacts with minimized reports. |
| MCP integration metadata | `trustweave mcp-profile-check` | Clear and review-required local profile artifacts with no server connection. |
| Interoperable review evidence | `trustweave sarif` | A deterministic local SARIF 2.1.0 file derived from selected review artifacts, with no automatic upload. |

## Acceptance controls

The safe reference candidate adds a synthetic external archive tool. A successful diff workflow must produce `TW-DIFF-001`, which confirms the diff engine did not silently ignore a new external capability. The default policy review must remain `clear`. The reference path from untrusted knowledge-base content to the archive tool must remain denied by the default policy.

The capability-growth candidate changes an existing synthetic sensitive tool by adding `customer-record.export`. A successful diff workflow must produce `TW-DIFF-003`, list the capability in its Markdown report, and preserve the distinction between a declared capability change and a runtime authorization decision.

The default policy’s conditional-to-external approval path must declare a human-review control that binds approval to the actor, tool, target, parameters, issue time, and expiry and fails closed. The deliberately incomplete approval fixture must return `1` under `policy-check --exit-on-review` and produce `TW-POL-004`. This verifies the evidence declaration and CI gate; it does not prove a production approval system exists.

The clear trace fixture must exit `0` with `--exit-on-review`. The review-required trace fixture must exit `1`, contain `TW-TRACE-004`, and omit the fixture’s mock recipient and message text from the Markdown report. These checks validate explicit review-gate semantics and the trace-report privacy boundary.

The clear MCP profile fixture must exit `0` with `--exit-on-review`. The review-required profile fixture must exit `1`, contain `TW-MCP-001`, and omit token-like query data from the Markdown report. These checks validate mapping drift, authorization-expectation review, URI hygiene, and the profile’s strict non-connection boundary.

A SARIF workflow must combine existing policy, diff, trace, and MCP review artifacts and retain `TW-POL-004`, `TW-DIFF-003`, `TW-TRACE-004`, and `TW-MCP-001` in `trustweave.sarif`. The artifact must declare SARIF version `2.1.0`. This is format-level interoperability evidence only; no hosted code-scanning upload occurs in the repository workflow.

A failing synthetic scenario, malformed manifest, unknown reference, invalid schema version, broken attestation chain, or missing review artifact is a release-blocking condition until the cause is understood and resolved.

## Hosted checks

The `Quality and tests` workflow repeats formatting, linting, core type checking, a Bandit static source-security scan, tests, repository-reality validation, package build, isolated wheel invocation, declared dependency audit, the synthetic evidence workflow, clear and review-required approval-boundary policy checks, baseline/candidate diff review, capability-growth diff review, clear-trace review, review-gate behavior, trace-report privacy assertions, clear MCP profile review, review-gate behavior, profile-URI hygiene assertions, and deterministic SARIF generation. It uploads generated evidence for inspection but does not upload SARIF to a code-scanning service.

The repository’s `main` branch requires this status check, retains linear history, and blocks force pushes and deletion. Direct commits remain the authorized working model; maintainers must complete the local checks before pushing and must monitor hosted results on the exact pushed SHA.

## Intentional coverage limits

TrustWeave does not have a database, a browser interface, a persistent deployment, or external service calls. Database migration checks, browser checks, deployment checks, and live-network testing are therefore not applicable to this version. These omissions are scope boundaries, not skipped security validation. Trace review is intentionally offline and does not authenticate a trace-producing system or establish runtime behavior beyond the local metadata supplied. MCP profile review is also offline; it does not validate a remote server, an OAuth deployment, or a token audience.
