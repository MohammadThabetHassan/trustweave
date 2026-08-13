# Release Guide

## Release status and contract

TrustWeave `0.1.1` is published on [PyPI](https://pypi.org/project/trustweave/0.1.1/) and tagged as [`v0.1.1`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.1.1). The release path is deliberately manual: a maintainer chooses the version, validates the exact commit, creates an annotated tag, and dispatches the dedicated publishing workflow. A green build does not by itself authorize publication.

The GitHub repository is the source of truth for code, documentation, schemas, and release workflows. Every future release must use an explicitly authorized commit identity and retain the project’s non-executing boundary.

## Evidence checklist

| Check | Required evidence |
| --- | --- |
| Formatting | `ruff format --check .` passes. |
| Linting | `ruff check .` passes. |
| Type checking | `mypy src` passes. |
| Test suite | `pytest` passes, including the 90% branch-coverage gate. |
| Static source security | `bandit -r src/trustweave -q` passes. |
| Repository reality | `python3 scripts/reality_check.py` passes for tracked docs, schemas, workflow YAML, and CLI references. |
| Package build | `python -m build` and `twine check dist/*` pass. |
| Isolated install | A fresh virtual environment installs the built wheel and verifies `trustweave --help` plus the package version. |
| Dependency and SBOM checks | Hosted CI performs declared-dependency audit and reproducible CycloneDX SBOM generation. |
| Reproducibility | Hosted CI verifies the fixed-epoch wheel build. |
| Compatibility | Hosted CI passes on the configured Python 3.11/3.13 and operating-system matrix. |
| Repository hygiene | The working tree is clean, generated artifacts are excluded, and documentation matches implementation. |

## Release flow

### 1. Prepare the release target

1. Choose the intended semantic version and verify it has not already been published.
2. Update `pyproject.toml`, `src/trustweave/__init__.py`, and `CHANGELOG.md` together.
3. Update user-facing installation, compatibility, release, and scope documentation when behavior or public claims change.
4. Run every applicable local evidence check from the table above.
5. Commit verified changes using an explicitly authorized identity and push directly to `main` when that remains the documented contribution model.
6. Wait for hosted CI on the exact pushed SHA. Resolve any failure with a new verified commit; never rewrite shared history to repair a release target.

### 2. Validate a candidate on TestPyPI

TestPyPI is the package-distribution rehearsal environment. The dedicated `.github/workflows/publish-testpypi.yml` workflow builds and checks distributions in an unprivileged job, then uploads them from a separate GitHub OIDC trusted-publishing job. It uses no stored upload token and disables package attestations pending separately authorized signing work.

A TestPyPI candidate should be published from an annotated release-candidate tag, then installed in a fresh virtual environment with an exact version pin. The release record should note the TestPyPI workflow URL, tag, artifact version, and clean-install result.

TrustWeave `0.1.1rc1` was intentionally retained as an immutable validation record after a clean install exposed an import-version mismatch. The corrected `0.1.1rc2` added a version-synchronization regression test and passed TestPyPI clean-install validation before the final `0.1.1` release target was prepared.

### 3. Publish to PyPI

Production publishing uses `.github/workflows/publish-pypi.yml`. The workflow is manually dispatched against an annotated final-version tag and has two jobs:

| Job | Authority | Responsibility |
| --- | --- | --- |
| `build` | Read-only repository contents | Checks out the tag, verifies the intended version, builds distributions, and runs `twine check`. |
| `publish` | `id-token: write` only | Downloads the verified distributions and publishes through PyPI trusted publishing. |

The publish job runs in the GitHub Actions environment named `pypi`. PyPI must have a matching pending or active GitHub trusted publisher for owner `MohammadThabetHassan`, repository `trustweave`, workflow `publish-pypi.yml`, and environment `pypi`. The workflow uses the PyPA publishing action without a stored PyPI token.

After publication, verify the production PyPI project page, install the exact version in a new virtual environment, assert that `trustweave.__version__` matches the release version, and run `trustweave --help` from the installed package.

### 4. Create the GitHub release record

After the production upload succeeds, create a non-draft GitHub release from the same annotated tag. Release notes must state material changes, verification evidence, intentional limits, and known compatibility impact. They must not claim production security certification, general prompt-injection prevention, externally signed provenance, or complete agent-system security.

## Post-release review

A release is complete only after the tag, GitHub release record, PyPI project page, clean installation, hosted CI, publishing workflow, branch protections, and working-tree state have been verified. Record remaining limitations in the changelog and roadmap, and conduct the governance/threat-model review on the documented cadence.

## Intentional release boundaries

Publishing TrustWeave packages does not make the tool execute agent tools, connect to MCP servers, call models, access credentials, send network traffic, upload SARIF, or provide runtime enforcement. The release workflows do not create an external signing or provenance claim because package attestations are disabled. Those capabilities require separate design and explicit maintainer authorization.
