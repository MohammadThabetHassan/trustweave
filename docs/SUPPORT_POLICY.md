# Support and Deprecation Policy

## Scope

This policy defines the maintained compatibility expectations for TrustWeave’s **local, non-executing evidence tool**. It applies to published package interfaces, documented schemas, deterministic evidence contracts, and release procedure. It does not create a hosted-service availability commitment, incident-response service-level agreement, runtime-security guarantee, or obligation to support an undeclared integration.

The authoritative machine-readable source is [`docs/contracts/compatibility-v1.json`](contracts/compatibility-v1.json). The repository validator checks that this policy, the compatibility guide, package metadata, CI matrix, public CLI surface, and maintained schema statements agree.

## Supported environment

TrustWeave requires **Python 3.11 or later**. The package metadata supports Python 3.11, 3.12, and 3.13. Hosted compatibility tests run on Python 3.11 and 3.13 across Ubuntu, macOS, and Windows; Python 3.12 remains a supported package metadata target and is exercised in the verified local release environment.

The supported public entry points are the installed `trustweave` command and `python -m trustweave`. Both expose the same command surface. `--version` and `-V` print the authoritative package version without configuration discovery, file writes, or network access.

## Versioning and deprecation

| Change type | Versioning expectation | Required evidence |
| --- | --- | --- |
| Patch release | Preserve documented CLI, input, output, and bounded-reader behavior while adding fixes, tests, documentation, or assurance controls. | Regression tests, compatibility validation, and release evidence. |
| Minor release | Add visible command behavior, a new emitted artifact contract, changed semantics, or a migration requirement. | Updated versioned contract, migration guidance, compatibility fixtures, and release notes. |
| Major release | Remove a documented reader, break CLI/output behavior, or alter the safety boundary. | Explicit migration plan, maintainer decision, release notes, and a major-version release. |

A documented interface is not removed silently. Deprecation requires clear documentation, a supported replacement where practical, a defined release boundary, and regression coverage through the stated support period. Historical local evidence remains readable only where a bounded reader and fixture prove the documented behavior; historical documents are never relabeled to appear current.

## Security and maintenance boundaries

The project accepts private vulnerability reports through the route in [`SECURITY.md`](../SECURITY.md). Security fixes are evaluated based on severity, reproducibility, scope, and maintainer capacity. The project does not promise response times, a managed service, automatic remediation, or an enforcement decision.

Compatibility support never changes TrustWeave’s core boundary: it does not execute agents, tools, application code, MCP servers, or models; contact remote systems; access credentials; upload results; or make deployment decisions.
