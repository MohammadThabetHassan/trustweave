# TestPyPI Release Preparation Checklist

This document prepares a future TestPyPI validation release. It does **not** authorize publication, create a package, use credentials, change repository visibility, or tag a release.

## Owner authorization gate

Before any publishing action, the repository owner must explicitly approve the target version, TestPyPI upload, package visibility, and any release tag. Publishing requires a configured trusted-publishing or token-based identity owned by the project; do not place tokens in repository files, examples, or CI logs.

## Pre-publication evidence

| Check | Required evidence |
|---|---|
| Exact target | Clean `main`, exact reviewed commit SHA, and green hosted CI on that SHA. |
| Package metadata | Correct project URLs, version, license, Python classifiers, README, and distribution contents. |
| Quality | Format, lint, typing, Bandit, 90% branch coverage, dependency audit, wheel reproducibility, SBOM, and repository-reality checks pass. |
| Safety contract | Documentation accurately states non-execution, non-connection, no credential access, and no runtime-security guarantee. |
| Release notes | Changelog entry and concise known limitations. |

## Future TestPyPI procedure

After authorization, build from the approved SHA in a clean environment, inspect both sdist and wheel, upload only to TestPyPI through the approved identity, then install the wheel in a fresh virtual environment from TestPyPI and run a harmless CLI help and local-fixture workflow. Record the exact package version, SHA, upload URL, installer command, and verification result in release notes.

A TestPyPI upload is not a PyPI release. PyPI publication requires a separate owner approval after TestPyPI validation succeeds.
