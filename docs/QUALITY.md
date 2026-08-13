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
| Policy structure | `trustweave policy-check` | A clear result for the default policy or documented review findings. |
| Change review | `trustweave diff` | Bundle-diff JSON and Markdown for a baseline/candidate pair. |
| Observed-evidence review | `trustweave trace-review` | Clear and review-required local trace artifacts with minimized reports. |
| MCP integration metadata | `trustweave mcp-profile-check` | Clear and review-required local profile artifacts with no server connection. |

## Acceptance controls

The safe reference candidate adds a synthetic external archive tool. A successful diff workflow must produce `TW-DIFF-001`, which confirms the diff engine did not silently ignore a new external capability. The default policy review must remain `clear`. The reference path from untrusted knowledge-base content to the archive tool must remain denied by the default policy.

The clear trace fixture must exit `0` with `--exit-on-review`. The review-required trace fixture must exit `1`, contain `TW-TRACE-004`, and omit the fixture’s mock recipient and message text from the Markdown report. These checks validate explicit review-gate semantics and the trace-report privacy boundary.

The clear MCP profile fixture must exit `0` with `--exit-on-review`. The review-required profile fixture must exit `1`, contain `TW-MCP-001`, and omit token-like query data from the Markdown report. These checks validate mapping drift, authorization-expectation review, URI hygiene, and the profile’s strict non-connection boundary.

A failing synthetic scenario, malformed manifest, unknown reference, invalid schema version, broken attestation chain, or missing review artifact is a release-blocking condition until the cause is understood and resolved.

## Hosted checks

The `Quality and tests` workflow repeats formatting, linting, core type checking, a Bandit static source-security scan, tests, package build, isolated wheel invocation, declared dependency audit, the synthetic evidence workflow, policy review, baseline/candidate diff review, clear-trace review, review-gate behavior, trace-report privacy assertions, clear MCP profile review, review-gate behavior, and profile-URI hygiene assertions. It uploads generated evidence for inspection.

The repository’s `main` branch requires this status check, retains linear history, and blocks force pushes and deletion. Direct commits remain the authorized working model; maintainers must complete the local checks before pushing and must monitor hosted results on the exact pushed SHA.

## Intentional coverage limits

TrustWeave does not have a database, a browser interface, a persistent deployment, or external service calls. Database migration checks, browser checks, deployment checks, and live-network testing are therefore not applicable to this version. These omissions are scope boundaries, not skipped security validation. Trace review is intentionally offline and does not authenticate a trace-producing system or establish runtime behavior beyond the local metadata supplied. MCP profile review is also offline; it does not validate a remote server, an OAuth deployment, or a token audience.
