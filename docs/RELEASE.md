# Release Procedure

## Preconditions

TrustWeave releases are authorized only after a maintainer confirms the target version, release notes, and repository visibility. This repository is currently intended to remain private. No release should be published until the private repository exists, direct-main commits are pushed under explicitly authorized identities, and hosted checks are green on the exact release commit.

## Evidence checklist

| Check | Required evidence |
|---|---|
| Formatting | `ruff format --check .` passes. |
| Linting | `ruff check .` passes. |
| Type checking | `mypy src` passes. |
| Test suite | `pytest` passes. |
| End-to-end workflow | The example creates a bundle, passing test result, attestation, report, and valid verification result. |
| Package build | A clean build/install succeeds in a supported Python environment. |
| Dependency review | Hosted dependency-review workflow is green for the release target. |
| CI | Hosted CI is green on the exact target commit. |
| Repository hygiene | Working tree is clean; generated artifacts are excluded; documentation reflects implementation. |

## Release steps

1. Confirm the repository visibility, authorized commit identity, target version, and release authorization.
2. Inspect the branch, remote, current commit, generated files, and working tree.
3. Run every local evidence check in the table above.
4. Update `CHANGELOG.md` with the actual version, release date, capabilities, and known intentional limits.
5. Commit only verified changes using an explicitly authorized identity and push directly to `main` if that remains the agreed policy.
6. Wait for CI and dependency-review checks on the exact pushed SHA. Resolve failures with new verified commits rather than rewriting shared history.
7. Verify the private repository’s settings, release target, and required branch protections. Do not claim protection has been enabled if repository-administrator access is unavailable.
8. Create an annotated semantic-version tag and publish a release only after the prior checks complete and explicit authorization is reconfirmed.
9. Record the release URL, tag, verification evidence, and remaining limits in the release notes.

## Production PyPI trusted publishing

Production PyPI publication is a separately authorized action. The release target must first pass the TestPyPI validation path, local evidence checklist, and hosted CI on its exact final commit.

The repository uses `.github/workflows/publish-pypi.yml` for production publication. It is manually dispatched against an annotated final-version tag, builds and checks distributions before publishing, and gives `id-token: write` only to the isolated publish job. The job uses the GitHub Actions environment named `pypi` and the PyPA trusted-publishing action without a stored PyPI token. PyPI must have a pending or active GitHub trusted publisher matching the owner `MohammadThabetHassan`, repository `trustweave`, workflow `publish-pypi.yml`, and environment `pypi`.

This route publishes package artifacts to PyPI but does not make the GitHub repository public, create runtime network behavior in TrustWeave, upload SARIF, connect to MCP servers, or add external signing. Any of those changes requires separate authorization.

## Release-note boundaries

Release notes must distinguish implemented behavior from planned work. They must not claim production security certification, general prompt-injection prevention, externally signed provenance, or complete agent-system security unless separately implemented and evidenced.
