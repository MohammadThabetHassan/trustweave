# Release Guide

## Release status and contract

TrustWeave `0.3.0` is an **unreleased assurance candidate**. TrustWeave `0.2.3` is the current published package, available from [PyPI](https://pypi.org/project/trustweave/0.2.3/), [TestPyPI](https://test.pypi.org/project/trustweave/0.2.3/), and [GitHub Release `v0.2.3`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.3). Its annotated tag targets `4aed7df9d16907804f8c2460c004a4dc685904bc`; TestPyPI and PyPI trusted-publishing workflows completed successfully, fresh installations from both indexes verified the console and module CLI entry points, and the exact wheels passed expected-repository provenance verification. [Release Evidence 0.2.3](RELEASE_EVIDENCE_0.2.3.md) preserves the URLs, hashes, commands, and workflow runs. Annotated `v0.2.0` is retained at `7232fe3a23d92f50a693903c0a6b7cb92d0a1426` as immutable unpublished audit evidence: it was never published to PyPI and has no GitHub Release. The release path remains deliberately manual for every future version: a maintainer validates the exact commit, creates an annotated tag, and dispatches the dedicated publishing workflow. A green build does not by itself authorize publication.

The GitHub repository is the source of truth for code, documentation, schemas, and release workflows. Every future release must use an explicitly authorized commit identity and retain the project’s non-executing boundary.

## Evidence checklist

| Check | Required evidence |
| --- | --- |
| Formatting | `ruff format --check .` passes. |
| Linting | `ruff check .` passes. |
| Type checking | `mypy src` passes. |
| Test suite | `pytest` passes, including the 95% branch-coverage gate. |
| Static source security | `bandit -r src/trustweave -q` passes. |
| Repository reality | `python3 scripts/reality_check.py` passes for tracked docs, schemas, workflow YAML, CLI references, golden evidence, traceability, clean distribution assurance, and configured package-provenance controls. |
| Golden evidence | `python scripts/verify_golden_evidence.py` matches the reviewed synthetic case inventory and canonical output digests without updating snapshots. |
| Traceability | `python scripts/verify_control_traceability.py` confirms every stated declaration-layer threat and out-of-scope risk is linked to its reviewed source contract. |
| Clean distribution assurance | `python scripts/verify_distribution_artifacts.py` builds exactly one wheel and source distribution, checks archive/package contents, and installs both in fresh temporary environments. |
| Package-attestation controls | `python scripts/verify_package_provenance_controls.py` confirms TestPyPI and PyPI workflows request attestations; the release record must distinguish configured controls from observed exact-file verification. |
| Package build | `python -m build` and `twine check dist/*` pass. |
| Isolated install | A fresh virtual environment installs the built wheel and verifies `trustweave --version`, `trustweave -V`, `trustweave --help`, `trustweave schema list`, and the import-visible package version. |
| Dependency and SBOM checks | Hosted CI performs declared-dependency audit and reproducible CycloneDX SBOM generation. |
| Reproducibility | Hosted CI verifies the fixed-epoch wheel build; before tagging, run `python3 scripts/verify_release_reproducibility.py --source-revision "$(git rev-parse HEAD)" --generated-at 2026-08-19T00:00:00+00:00` to verify two temporary configured staged-CI runs, byte-identical artifacts, path hygiene, and supplied-file attestation bindings. |
| Compatibility | Hosted CI passes on the configured Python 3.11/3.13 and operating-system matrix. |
| Repository hygiene | The working tree is clean, generated artifacts are excluded, and documentation matches implementation. |

## Release flow

### 1. Prepare the release target

1. Choose the intended semantic version and verify it has not already been published.
2. Update `pyproject.toml`, `src/trustweave/__init__.py`, `CITATION.cff`, and `CHANGELOG.md` together.
3. Update user-facing installation, compatibility, release, and scope documentation when behavior or public claims change.
4. Run every applicable local evidence check from the table above.
5. Commit verified changes using an explicitly authorized identity and push directly to `main` when that remains the documented contribution model.
6. Wait for hosted CI on the exact pushed SHA. Resolve any failure with a new verified commit; never rewrite shared history to repair a release target.

### 2. Validate a candidate on TestPyPI

TestPyPI is the package-distribution rehearsal environment. The dedicated `.github/workflows/publish-testpypi.yml` workflow builds and checks distributions in an unprivileged job, then uploads them from a separate GitHub OIDC trusted-publishing job. It uses no stored upload token and requests PyPI project attestations for its distribution files.

A TestPyPI candidate must be published from an annotated release-candidate tag, then installed in a fresh virtual environment with an exact version pin. The verifier’s direct URL mode accepts production `files.pythonhosted.org` URLs, not `test-files.pythonhosted.org`; before production promotion, download the exact TestPyPI wheel with its original filename, retrieve the matching TestPyPI Integrity API provenance object, and run `pypi-attestations verify pypi --repository https://github.com/MohammadThabetHassan/trustweave --provenance-file <provenance-file> <exact-wheel-file>`. The release record must preserve the TestPyPI workflow URL, tag, artifact filename, version, SHA-256, provenance URL, verifier output, expected repository identity, and clean-install result. Attestation generation alone is not authenticated-provenance evidence until this observed verification succeeds.

TrustWeave `0.1.1rc1` was intentionally retained as an immutable validation record after a clean install exposed an import-version mismatch. The corrected `0.1.1rc2` added a version-synchronization regression test and passed TestPyPI clean-install validation before the final `0.1.1` release target was prepared.

### 3. Publish to PyPI

Production publishing uses `.github/workflows/publish-pypi.yml`. The workflow is manually dispatched against an annotated final-version tag and has two jobs:

| Job | Authority | Responsibility |
| --- | --- | --- |
| `build` | Read-only repository contents | Checks out the tag, verifies the intended version, builds distributions, and runs `twine check`. |
| `publish` | `id-token: write` only | Downloads the verified distributions and publishes through PyPI trusted publishing. |

The publish job runs in the GitHub Actions environment named `pypi`. PyPI must have a matching pending or active GitHub trusted publisher for owner `MohammadThabetHassan`, repository `trustweave`, workflow `publish-pypi.yml`, and environment `pypi`. The workflow uses the PyPA publishing action without a stored PyPI token.

After publication, verify the production PyPI project page, install the exact version in a new virtual environment, assert that `trustweave.__version__` matches the release version, and run `trustweave --version`, `trustweave -V`, `trustweave --help`, and `trustweave schema list` from the installed package. Then verify the exact PyPI file with the official `pypi-attestations` procedure and expected repository identity; only then may the release notes and provenance guide describe that exact package file as authenticated provenance evidence.

### 4. Create the GitHub release record

After the production upload succeeds, create a non-draft GitHub release from the same annotated tag. Release notes must state material changes, verification evidence, intentional limits, and known compatibility impact. They must not claim production security certification, general prompt-injection prevention, unobserved authenticated package provenance, or complete agent-system security.

## Post-release review

A release is complete only after the tag, GitHub release record, PyPI project page, clean installation, expected-repository verification, hosted CI, publishing workflow, branch protections, and working-tree state have been verified. Record the exact-file provenance result in a versioned release-evidence record, list remaining limitations in the changelog and roadmap, and conduct the governance/threat-model review on the documented cadence.

## Intentional release boundaries

Publishing TrustWeave packages does not make the tool execute agent tools, connect to MCP servers, call models, access credentials, send network traffic, upload SARIF, or provide runtime enforcement. Configuring PyPI project-attestation generation does not itself create a release-provenance claim; that claim is limited to an exact published file only after its independent expected-repository verification is recorded. The package runtime boundary remains unchanged.
