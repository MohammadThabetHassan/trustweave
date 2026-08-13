# Quality Evidence Guide

## Purpose

TrustWeave makes security-related review claims only when they are linked to reproducible artifacts. This guide defines the checks that maintainers must execute before a direct commit to `main` and before a release.

## Local verification

Run the following commands from a clean checkout. The package requires Python 3.11 or later; the repository CI currently verifies Python 3.12.

```bash
python -m pip install -e . build pip-audit pytest ruff mypy PyYAML

ruff format --check .
ruff check .
mypy src
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

## Acceptance controls

The safe reference candidate adds a synthetic external archive tool. A successful diff workflow must produce `TW-DIFF-001`, which confirms the diff engine did not silently ignore a new external capability. The default policy review must remain `clear`. The reference path from untrusted knowledge-base content to the archive tool must remain denied by the default policy.

A failing synthetic scenario, malformed manifest, unknown reference, invalid schema version, broken attestation chain, or missing review artifact is a release-blocking condition until the cause is understood and resolved.

## Hosted checks

The `Quality and tests` workflow repeats formatting, linting, core type checking, tests, package build, isolated wheel invocation, declared dependency audit, the synthetic evidence workflow, policy review, and baseline/candidate diff review. It uploads generated evidence for inspection.

The repository’s `main` branch requires this status check, retains linear history, and blocks force pushes and deletion. Direct commits remain the authorized working model; maintainers must complete the local checks before pushing and must monitor hosted results on the exact pushed SHA.

## Intentional coverage limits

TrustWeave does not have a database, a browser interface, a persistent deployment, or external service calls. Database migration checks, browser checks, deployment checks, and live-network testing are therefore not applicable to this version. These omissions are scope boundaries, not skipped security validation.
