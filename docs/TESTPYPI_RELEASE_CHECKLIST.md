# TestPyPI Validation Guide

## Purpose

TestPyPI is a separate package index used to validate TrustWeave distribution artifacts and the GitHub OIDC trusted-publishing path before a production PyPI release. It is not a production distribution channel and does not replace final release authorization, hosted CI, or a production clean-install check.

## Completed validation record

| Version | Purpose | Result |
| --- | --- | --- |
| `0.1.1rc1` | First trusted-publisher rehearsal. | Uploaded successfully; a clean install exposed an immutable mismatch between package metadata and `trustweave.__version__`. |
| `0.1.1rc2` | Corrected candidate with version-synchronization regression coverage. | Uploaded successfully and passed an exact-version clean install plus CLI verification. |
| `0.1.1` | Final production release target. | Published to production PyPI only after the corrected TestPyPI validation, full local evidence, hosted CI, and production OIDC workflow passed. |

The retained `0.1.1rc1` record is intentional: it demonstrates that the validation path found a real packaging mismatch before production publication. The fix in `0.1.1rc2` added a deterministic test requiring the import-visible version to match `pyproject.toml`.

## Reusable validation procedure

### Preconditions

Before publishing a candidate, confirm the candidate version is unique, `pyproject.toml` and `src/trustweave/__init__.py` agree, the changelog describes the candidate accurately, local quality checks pass, and hosted CI is green on the exact candidate commit. The candidate should be an annotated tag, not an uncommitted working tree.

A TestPyPI pending or active GitHub trusted publisher must match owner `MohammadThabetHassan`, repository `trustweave`, workflow `publish-testpypi.yml`, and any environment declared by that workflow. The workflow uses GitHub OIDC and no stored upload token.

### Publish and validate

1. Create and push an annotated release-candidate tag.
2. Manually dispatch `.github/workflows/publish-testpypi.yml` against that tag with the exact expected version.
3. Wait for the isolated build and publish jobs to succeed.
4. Confirm the package page and simple index list the expected wheel and source distribution.
5. In a new virtual environment, install the exact candidate from TestPyPI and assert both the import-visible package version and CLI help surface.

```bash
python -m venv /tmp/trustweave-testpypi-venv
/tmp/trustweave-testpypi-venv/bin/pip install \
  --no-cache-dir \
  --index-url https://test.pypi.org/simple/ \
  "trustweave==<candidate-version>"
/tmp/trustweave-testpypi-venv/bin/python -c \
  "import trustweave; print(trustweave.__version__)"
/tmp/trustweave-testpypi-venv/bin/trustweave --help
rm -rf /tmp/trustweave-testpypi-venv
```

If the simple index is still propagating immediately after a successful upload, inspect its listing before retrying the clean install. Do not change or reuse an already-published candidate version; publish a new candidate after fixing the underlying issue.

## Boundaries

This procedure publishes package artifacts only. It does not make the repository public, create production PyPI artifacts, enable runtime behavior in TrustWeave, add external signing, upload SARIF, connect to MCP servers, execute tools, access credentials, or call models. See the [release guide](RELEASE.md) for the production path.
