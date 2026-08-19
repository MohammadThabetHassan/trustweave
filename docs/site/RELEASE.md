# Release process and owner-controlled publication

TrustWeave [`0.2.1`](https://pypi.org/project/trustweave/0.2.1/) is the completed public release, available as [GitHub Release `v0.2.1`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.1). Its annotated tag targets `f1394d5fba8a0fbc24e3a18f45702e83aa65645e`; TestPyPI and PyPI trusted publishing completed successfully. A future pull request still does **not** authorize a tag, publication, or public release by itself. Annotated `v0.2.0` remains an immutable unpublished audit tag and must not be reused or published from.

## Repository-controlled evidence

Before owner review, the release branch must have a clean working tree and verified formatting, linting, strict typing, tests with the 95% branch-coverage gate, static source security, reality checks, strict documentation build, package build, Twine metadata validation, dependency audit, and hosted compatibility/workflow checks. The PR evidence matrix records results for the exact checked commit.

## Owner-controlled sequence

| Step | Required owner action | Boundary |
| --- | --- | --- |
| Merge | Review and merge a release PR into `main` | The exact merged SHA is the only valid release candidate |
| TestPyPI | Dispatch the TestPyPI workflow for the exact merged commit or approved release-candidate tag | Publishing a candidate remains a maintainer decision |
| Candidate validation | Install the exact TestPyPI version in a fresh environment and run package/CLI smoke checks | Results must be recorded from the real distribution |
| Production | Create an approved annotated release tag and dispatch the production PyPI workflow | Trusted publishing and tags require owner authorization |
| GitHub Release | Create the non-draft release from the same final tag with evidence-based notes | Release notes must state limitations honestly |

The PyPI workflows use GitHub OIDC trusted publishing rather than stored upload tokens. A green build does not grant the authority to trigger these workflows, create tags, or make a release public.

## Post-publication verification

After a successful production workflow, verify the PyPI project page, install the exact released version in a new virtual environment, confirm `trustweave.__version__`, and run `trustweave --help`. Ensure the GitHub release, production tag, workflow records, published package version, and release notes refer to the same commit.

> Publishing does not change TrustWeave’s product boundary. The package remains a local, deterministic, non-executing evidence tool; it does not execute declared agents or tools, connect to MCP servers, read credentials, upload SARIF, or enforce a deployed runtime.
