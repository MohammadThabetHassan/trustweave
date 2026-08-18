# Quality Evidence Guide

## Purpose

TrustWeave makes security-related review claims only when they are linked to reproducible artifacts. This guide defines the checks required on an open pull-request head before merge and before an owner-authorized release.

## Local verification

Run the following commands from a clean checkout. The package requires Python 3.11 or later. The primary quality workflow verifies Python 3.12, and separate compatibility jobs run the full test suite on Python 3.11 and 3.13.

```bash
python -m pip install -e ".[dev]" bandit build pip-audit

ruff format --check .
ruff check .
mypy src
bandit -r src/trustweave -q
pytest
python -m build
pip-audit -r requirements.txt
twine check dist/*
SOURCE_DATE_EPOCH=0 python -m build --wheel --outdir .wheel-repro-a
SOURCE_DATE_EPOCH=0 python -m build --wheel --outdir .wheel-repro-b
cmp .wheel-repro-a/*.whl .wheel-repro-b/*.whl
cyclonedx-py environment "$(which python)" --pyproject pyproject.toml --mc-type library --output-reproducible --output-file artifacts/trustweave.cdx.json
```

The declared core runtime dependency set is intentionally empty in v0.1. Optional YAML parsing and developer tools are declared as package extras. An audit that reports no declared runtime packages is therefore expected and must not be described as an audit of the entire developer workstation.

## Required evidence workflows

| Workflow | Command | Expected evidence |
|---|---|---|
| Core bundle | `trustweave scan` | A validated `trustweave.dev/bundle/v1alpha2` `agent-security-bundle.json` with explicit flow decisions and limits. |
| Synthetic regression | `trustweave test` | Passing `security-test-results.json` for the baseline and cited adversarial scenario packs. |
| Scenario explanation | `trustweave explain` | Local Markdown explanation with declared taxonomy references and no model or network action. |
| Static MCP snapshot inventory | `trustweave mcp-import` | Sorted local `mcp-tool-inventory.json` with no discovery, connection, authorization inference, or invocation. |
| Branch coverage | `pytest` | Release-blocking 95% branch coverage across the `trustweave` package. |
| Wheel reproducibility | Two fixed-epoch wheel builds | Byte-for-byte identical wheels from the same working tree. |
| Local SBOM | `cyclonedx-py environment --output-reproducible` | Reproducible CycloneDX evidence for the verified Python environment and project metadata. |
| Local integrity | `trustweave attest` then `trustweave verify` | An internally consistent hash-linked attestation. |
| Policy structure | `trustweave policy-check --exit-on-review` | A clear default-policy review with a documented, bound, fail-closed approval boundary, or an explicit non-zero review gate. |
| Change review | `trustweave diff` | Bundle-diff JSON and Markdown for baseline/candidate and capability-growth pairs. |
| Repository reality | `python scripts/reality_check.py` | Verified local Markdown links, JSON schemas, byte-identical source/package schema resources, versioned generated-artifact schema coverage, workflow YAML, and documented CLI commands. |
| Observed-evidence review | `trustweave trace-review` | Clear and review-required local trace artifacts with minimized reports. |
| MCP integration metadata | `trustweave mcp-profile-check` | Clear and review-required local profile artifacts with no server connection. |
| Interoperable review evidence | `trustweave sarif` | A deterministic local SARIF 2.1.0 file derived from selected review artifacts, with no automatic upload. |
| High-risk mutation analysis | `mutmut run` then `mutmut results` | A Linux-only diagnostic of the configured twelve-module evidence, configuration, policy, risk, schema, SARIF, and CI-coordination scope; see [the mutation-testing record](MUTATION_TESTING.md). |

## Acceptance controls

The safe reference candidate adds a synthetic external archive tool. A successful diff workflow must produce `TW-DIFF-001`, which confirms the diff engine did not silently ignore a new external capability. The default policy review must remain `clear`. The reference path from untrusted knowledge-base content to the archive tool must remain denied by the default policy.

The capability-growth candidate changes an existing synthetic sensitive tool by adding `customer-record.export`. A successful diff workflow must produce `TW-DIFF-003`, list the capability in its Markdown report, and preserve the distinction between a declared capability change and a runtime authorization decision.

The default policy’s conditional-to-external approval path must declare a human-review control that binds approval to the actor, tool, target, parameters, issue time, and expiry and fails closed. The deliberately incomplete approval fixture must return `1` under `policy-check --exit-on-review` and produce `TW-POL-004`. This verifies the evidence declaration and CI gate; it does not prove a production approval system exists.

The clear trace fixture must exit `0` with `--exit-on-review`. The review-required trace fixture must exit `1`, contain `TW-TRACE-004`, and omit the fixture’s mock recipient and message text from the Markdown report. These checks validate explicit review-gate semantics and the trace-report privacy boundary.

The clear MCP profile fixture must exit `0` with `--exit-on-review`. The review-required profile fixture must exit `1`, contain `TW-MCP-001`, and omit token-like query data from the Markdown report. These checks validate mapping drift, authorization-expectation review, URI hygiene, and the profile’s strict non-connection boundary.

The adversarial scenario library must pass all **25** cited synthetic patterns under the default policy, and `explain` must render the reference for `TW-ADV-001`. The MCP tools-list fixture must normalize to a two-tool inventory without an endpoint, transport operation, credential, action-class inference, or invocation.

The high-risk mutation analysis recorded in [MUTATION_TESTING.md](MUTATION_TESTING.md) covers twelve high-risk modules on Linux because mutmut requires fork support. The final run exceeds the enforced **95%** threshold and is a release-blocking control for the declared scope, not a claim about the entire package or a security certification. The hosted gate requires exact survivor-identifier parity, exact normalized-diff parity, no duplicate or stale records, zero untriaged survivors, zero `needs_regression` classifications, non-empty rationales, and internally consistent totals on the exact reviewed SHA.

The repository-reality check requires every current generated artifact version to have an exact public JSON Schema linked to its producer, and requires each published schema to be byte-identical to its packaged resource. It also requires maintained documentation to name current bundle, risk-review, fingerprint, configuration, coverage, and mutation evidence markers. The dedicated conformance suite validates real local output for policy review, synthetic tests, current bundle diffs, trace review, MCP reviews and inventories, framework inventory, scaffolds, unsigned statements, and current risk-review outputs.

A SARIF workflow must combine existing policy, diff, trace, and MCP review artifacts and retain `TW-POL-004`, `TW-DIFF-003`, `TW-TRACE-004`, and `TW-MCP-001` in `trustweave.sarif`. The artifact must declare SARIF version `2.1.0`. This is format-level interoperability evidence only; no hosted code-scanning upload occurs in the repository workflow.

A failing synthetic scenario, malformed manifest, unknown reference, invalid schema version, broken attestation chain, or missing review artifact is a release-blocking condition until the cause is understood and resolved.

## Hosted checks

The `Quality and tests` workflow repeats formatting, linting, core type checking, a Bandit static source-security scan, the enforced 95% branch-coverage test suite, repository-reality validation, package build, isolated wheel invocation, deterministic wheel reproducibility, declared dependency audit, reproducible CycloneDX SBOM generation, the synthetic evidence workflow, cited adversarial-scenario checks, local MCP tools-list import, clear and review-required approval-boundary policy checks, baseline/candidate diff review, capability-growth diff review, clear-trace review, review-gate behavior, trace-report privacy assertions, clear MCP profile review, review-gate behavior, profile-URI hygiene assertions, and deterministic SARIF generation. Separate compatibility jobs run the test suite on Python 3.11 and 3.13. The workflow uploads generated evidence for inspection but does not upload SARIF to a code-scanning service.

Maintainers must complete the local checks before pushing a pull-request head and monitor hosted results on that exact pushed SHA. Merge, tagging, signing, TestPyPI/PyPI publication, and GitHub Release creation remain owner-controlled actions and are outside ordinary quality verification.

## Intentional coverage limits

TrustWeave does not have a database, a browser interface, a persistent deployment, or external service calls. Database migration checks, browser checks, deployment checks, and live-network testing are therefore not applicable to this version. These omissions are scope boundaries, not skipped security validation. Trace review is intentionally offline and does not authenticate a trace-producing system or establish runtime behavior beyond the local metadata supplied. MCP profile review is also offline; it does not validate a remote server, an OAuth deployment, or a token audience.
