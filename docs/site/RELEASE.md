# Release process and owner-controlled publication

TrustWeave [`0.3.0`](https://pypi.org/project/trustweave/0.3.0/) is the completed observed public release, available as [GitHub Release `v0.3.0`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.3.0). Its annotated tag targets `30308f47e84025315de2083047039e7efe0fd0ae`; TestPyPI and PyPI trusted publishing completed successfully, fresh installations from both indexes verified the console and module CLI entry points, and the exact published wheels passed expected-repository provenance verification. [Release Evidence 0.3.0](RELEASE_EVIDENCE_0.3.0.md) records the file URLs, hashes, workflow runs, and commands. Source metadata can contain an unreleased `0.3.1` candidate; it has no tag, public package file, GitHub Release, or fresh exact-file provenance record until the owner-authorized publication sequence completes. A future pull request still does **not** authorize a tag, publication, or public release by itself. Annotated `v0.2.0` remains an immutable unpublished audit tag and must not be reused or published from.

## Repository-controlled evidence

Before owner review, the release branch must have a clean working tree and verified formatting, linting, strict typing, tests with the 95% branch-coverage gate, static source security, reality checks, strict documentation build, golden evidence, threat-control-test traceability, clean distribution assurance, package-provenance workflow controls, package build, Twine metadata validation, dependency audit, and hosted compatibility/workflow checks. The PR evidence matrix records results for the exact checked commit.

## Owner-controlled sequence

| Step | Required owner action | Boundary |
| --- | --- | --- |
| Merge | Review and merge a release PR into `main` | The exact merged SHA is the only valid release candidate |
| TestPyPI | Dispatch the TestPyPI workflow for the exact merged commit or approved release-candidate tag | Publishing a candidate remains a maintainer decision |
| Candidate validation | Install the exact TestPyPI version in a fresh environment, run package/CLI/schema smoke checks, download the exact wheel and TestPyPI Integrity API provenance, then verify through `pypi-attestations verify pypi --repository https://github.com/MohammadThabetHassan/trustweave --provenance-file <provenance> <wheel>` | Generation is not a provenance claim until expected-repository verification is recorded for the real distribution |
| Production | Create an approved annotated release tag and dispatch the production PyPI workflow | Trusted publishing and tags require owner authorization |
| GitHub Release | Create the non-draft release from the same final tag with evidence-based notes | Release notes must state limitations honestly |

The PyPI workflows use GitHub OIDC trusted publishing rather than stored upload tokens. A green build does not grant the authority to trigger these workflows, create tags, or make a release public.

## Post-publication verification

After a successful production workflow, verify the PyPI project page, install the exact released version in a new virtual environment, confirm `trustweave.__version__`, and run `trustweave --help`. Verify the exact PyPI file with `pypi-attestations` against `https://github.com/MohammadThabetHassan/trustweave`, and retain the package URL, SHA-256, workflow URL, tag, verifier output, and clean-install evidence in a versioned release-evidence record. Ensure the GitHub release, production tag, workflow records, published package version, and release notes refer to the same commit.

> Publishing does not change TrustWeave’s product boundary. The package remains a local, deterministic, non-executing evidence tool; it does not execute declared agents or tools, connect to MCP servers, read credentials, upload SARIF, or enforce a deployed runtime.
