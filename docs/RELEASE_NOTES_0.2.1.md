# TrustWeave 0.2.1 Release Notes

> **Release status:** `0.2.1` is the corrected owner-controlled release target. It does not authorize a tag, signature, package publication, GitHub Release, merge, deployment, or credential use. Those actions remain owner-controlled after every required local and hosted gate is green on the exact reviewed SHA.

## Why 0.2.1 exists

The repository created annotated tag `v0.2.0` at `7232fe3a23d92f50a693903c0a6b7cb92d0a1426` during pre-publication verification. The verification process correctly stopped because `trustweave --version` was not available as a top-level command. The tag was never published to PyPI, and no GitHub Release was created for it.

> `v0.2.0` remains an immutable unpublished audit record. It must not be moved, deleted, reused, or published from. TrustWeave `0.2.1` is the corrected public release target.

## Corrected public version contract

| Command or metadata source | Required result |
| --- | --- |
| `trustweave --version` | Prints only `0.2.1` and exits `0`. |
| `trustweave -V` | Prints only `0.2.1` and exits `0`. |
| `python -c "import trustweave; print(trustweave.__version__)"` | Prints `0.2.1`. |
| `pyproject.toml` | Declares package version `0.2.1`. |
| Built wheel and source distribution | Report version `0.2.1`. |

The two CLI flags work without a subcommand, write nothing to standard error, do not discover project configuration, and do not create files or perform network activity. The parser obtains their value from the import-visible package version rather than a separate CLI literal. Regression coverage exercises source-checkout and installed-wheel console-script behavior.

## Retained release-quality controls

TrustWeave remains a local, deterministic review tool for supplied declarations and metadata. It does not execute agents, models, tools, MCP servers, shell commands from declarations, or network operations. The corrected release path retains the clean-checkout staged-CI verifier, fixed-provenance byte comparison, supplied-file attestation verification, schema resource checks, complete mutation gate, isolated-wheel verification, dependency audit, reproducible SBOM evidence, and cross-platform hosted checks.

The complete twelve-module mutation campaign must continue to meet the documented 95% threshold and exact survivor ID plus normalized-diff parity requirements, with zero untriaged and zero `needs_regression` records on the exact reviewed SHA.

## Upgrade and migration guidance

The functional evidence contracts prepared during 0.2.0 hardening remain the basis for 0.2.1. Users moving from `0.1.1` should follow [the migration guide](MIGRATION_GUIDE_0.2.0.md) for strict local declaration, bundle, and reviewer-decision handling, then install only an owner-published `0.2.1` artifact after verifying its release record.

Before any publication, the owner must follow [the 0.2.1 checklist](OWNER_RELEASE_CHECKLIST_0.2.1.md). A green build, an unpublished tag, or a passing subset of checks does not authorize publication.

## Known limits

The product remains deliberately non-executing and local-first. Its outputs are review evidence, not runtime enforcement, authorization, remediation, approval records, signed attestations, or external security certification. Fixed-epoch wheel verification is evidence for the documented build environment and inputs; it does not prove reproducibility across all operating systems, Python versions, source trees, or build backends.
