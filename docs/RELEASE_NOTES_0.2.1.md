# TrustWeave 0.2.1 Release Notes

> **Release status:** `0.2.1` is the completed corrected public release. Annotated tag [`v0.2.1`](https://github.com/MohammadThabetHassan/trustweave/tree/v0.2.1) targets `f1394d5fba8a0fbc24e3a18f45702e83aa65645e`; the [GitHub Release](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.1), [TestPyPI package](https://test.pypi.org/project/trustweave/0.2.1/), and [PyPI package](https://pypi.org/project/trustweave/0.2.1/) are published. The protected trusted-publishing workflows and clean installations completed successfully.

## Why 0.2.1 exists

The repository created annotated tag `v0.2.0` at `7232fe3a23d92f50a693903c0a6b7cb92d0a1426` during pre-publication verification. The verification process correctly stopped because `trustweave --version` was not available as a top-level command. The tag was never published to PyPI, and no GitHub Release was created for it.

> `v0.2.0` remains an immutable unpublished audit record. It must not be moved, deleted, reused, or published from. TrustWeave `0.2.1` is the corrected public release.

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

The functional evidence contracts prepared during 0.2.0 hardening remain the basis for 0.2.1. Users moving from `0.1.1` should follow [the migration guide](MIGRATION_GUIDE_0.2.0.md) for strict local declaration, bundle, and reviewer-decision handling, then install the published [`trustweave==0.2.1`](https://pypi.org/project/trustweave/0.2.1/) artifact.

The completed [0.2.1 release record](OWNER_RELEASE_CHECKLIST_0.2.1.md) retains the exact tag target, hosted-gate evidence, artifact verification, trusted-publication workflow records, and the preserved `v0.2.0` audit boundary.

## Known limits

The product remains deliberately non-executing and local-first. Its outputs are review evidence, not runtime enforcement, authorization, remediation, approval records, signed attestations, or external security certification. Fixed-epoch wheel verification is evidence for the documented build environment and inputs; it does not prove reproducibility across all operating systems, Python versions, source trees, or build backends.
