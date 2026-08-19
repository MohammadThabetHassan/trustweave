# Distribution Assurance

## Purpose

`python scripts/verify_distribution_artifacts.py` is the release-candidate distribution check for a **clean repository checkout**. It creates all build and installation state in a temporary directory beneath the checkout, removes that directory when finished, and refuses to run against a dirty tree unless the test-only `--allow-dirty` flag is supplied.

> The helper verifies locally built package artifacts. It does not publish to PyPI or TestPyPI, sign an artifact, contact a registry, establish package provenance, or prove that an artifact served by a third party is the one it built.

## What the check verifies

| Stage | Evidence checked |
| --- | --- |
| Build | Produces exactly one wheel and one source distribution from the local checkout. |
| Archive safety | Rejects absolute or parent-traversal archive member paths before relying on archive contents. |
| Wheel contract | Requires package metadata matching `pyproject.toml`, `trustweave`, `python -m trustweave`, `py.typed`, and packaged JSON schemas. |
| Source-distribution contract | Requires the project build metadata, package initializer, module entry point, typing marker, and packaged schemas. |
| Isolated wheel install | Installs the local wheel with `--no-deps` in a fresh virtual environment and checks console/module version commands, help, and schema resources. |
| Isolated source install | Performs the same checks after installing the local source distribution in a second fresh virtual environment. |
| Checkout hygiene | Compares `git status --porcelain` before and after the temporary operation. |

## Run from a clean checkout

```bash
python scripts/verify_distribution_artifacts.py
```

The helper intentionally installs only the local artifact with `pip --no-deps`. It therefore checks the package’s declared no-runtime-dependency installation path, rather than silently resolving unrelated dependencies from an index. The command is appropriate before a release and in a clean hosted checkout.

During local implementation work, maintainers may use the test-only escape hatch to exercise the temporary artifact checks before committing:

```bash
python scripts/verify_distribution_artifacts.py --allow-dirty
```

The escape hatch is not release evidence. The verified release command remains the clean-checkout form with no flag.

## Interpretation limits

A passing result proves that this checkout built package archives with the checked package files and that each archive installed and exposed the expected local command/resource contracts in a newly created virtual environment. It does not prove byte-for-byte reproducibility across platforms, dependency supply-chain security, registry publication, external attestation, repository identity, or runtime behavior beyond the checked commands and resources.
