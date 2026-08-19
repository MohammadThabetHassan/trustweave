# Owner Release Checklist: TrustWeave 0.2.1

> **Owner control:** This checklist records the conditions for an owner-authorized TrustWeave `0.2.1` release. It does not authorize a contributor or agent to merge, move tags, publish packages, create a GitHub Release, sign artifacts, alter branch protection, or change release settings outside the explicit owner-controlled sequence below.

> **Preserved audit boundary:** The existing annotated `v0.2.0` tag targets `7232fe3a23d92f50a693903c0a6b7cb92d0a1426`. It was created during pre-publication verification, was never published to PyPI, and has no GitHub Release. Do not move, delete, reuse, or publish from it. Treat it and its local artifacts as immutable unpublished audit evidence.

## A. Pre-merge acceptance gate

| Gate | Owner evidence required | Status to record |
| --- | --- | --- |
| Correct branch | The corrective PR targets `main`; no direct corrective commit was made to `main`. | PR URL and exact head SHA. |
| Version contract | `pyproject.toml`, `trustweave.__version__`, `CITATION.cff`, changelog, release notes, and this checklist identify `0.2.1`. | Reviewed paths and output. |
| CLI version contract | `trustweave --version`, `trustweave -V`, and `python -c "import trustweave; print(trustweave.__version__)"` each report exactly `0.2.1`. | Source and installed-wheel command output. |
| Side-effect boundary | Both CLI version flags exit `0`, write only the version plus newline to stdout, write nothing to stderr, require no subcommand, and do not discover configuration, write files, or access the network. | Regression-test evidence. |
| Mutation threshold | The twelve-module run is at least 95% killed. | Generated, killed, survived, and score. |
| Survivor triage | Exact survivor-ID and normalized-diff parity hold; `untriaged_count == 0`; `needs_regression == 0`; every retained equivalent/defensive record has a rationale. | Hosted mutation evidence artifact. |
| Documentation | Current release, migration, reproducibility, and rollback guidance identify `0.2.1` while preserving `v0.2.0` only as an unpublished audit record. | Reviewed changed paths. |
| Local checks | Formatter, lint, types, Bandit, tests, repository reality, strict documentation build, artifact checks, and dependency audit pass. | Exact local command output. |
| Hosted checks | All required checks are green on the exact final PR SHA. | Check names and URLs. |

Do **not** approve merge readiness unless the final hosted mutation gate reports zero untriaged and zero `needs_regression` survivors on the exact reviewed SHA.

## B. Required final verification commands

Run from a clean checkout of the approved PR head SHA.

```bash
ruff format --check .
ruff check .
mypy src
bandit -r src/trustweave -q
pytest
python3 scripts/reality_check.py
mkdocs build --strict

rm -rf mutants .mutmut-cache
mutmut run
mutmut results
```

Run the directly executable clean-checkout staged-CI verifier. It creates two temporary run directories and a separate explicit temporary `trustweave.toml` in each directory; it never relies on or creates a repository-root configuration file.

```bash
python3 scripts/verify_release_reproducibility.py \
  --source-revision "$(git rev-parse HEAD)" \
  --generated-at 2026-08-19T00:00:00+00:00
```

The helper uses tracked local fixtures, compares two ten-artifact trees byte-for-byte, rejects temporary and checkout-path leakage, verifies supplied-file v1alpha3 attestations, removes its temporary directories, and confirms that the working tree is unchanged. See [REPRODUCIBILITY.md](REPRODUCIBILITY.md) for scope and limits.

## C. Artifact verification after an owner-authorized release build

Only after all pre-merge and hosted gates are green, build the wheel and sdist exactly once from the verified `v0.2.1` tag. Before any authorized publication, verify the exact artifacts in a new isolated environment.

```bash
python -m build
python -m twine check dist/*
python -m pip install --force-reinstall dist/trustweave-0.2.1-py3-none-any.whl
trustweave --version
trustweave -V
python -c "import trustweave; print(trustweave.__version__)"
trustweave --help
trustweave schema list
python -m pip check
pip-audit -r requirements.txt
```

All three version commands must report exactly `0.2.1`. Confirm that wheel and sdist metadata, citation metadata, changelog, release notes, and import-visible `trustweave.__version__` all identify `0.2.1`; inspect packaged schemas and `py.typed`; retain the generated SBOM and SHA-256 checksums with the exact artifact bytes.

## D. Owner-authorized merge and release sequence

After the acceptance table is entirely green, the owner may choose to perform the following actions manually, subject to repository policy.

1. Merge the reviewed corrective PR using the approved method and record the resulting `main` SHA.
2. Re-run or confirm required hosted checks on that exact merge result and repeat the clean-checkout checklist.
3. Confirm that local and remote `v0.2.1`, GitHub Release `0.2.1`, and PyPI `trustweave==0.2.1` do not already exist.
4. Create an annotated `v0.2.1` tag only on the verified `main` SHA.
5. Build, inspect, and verify the wheel and sdist exactly once from that tag; retain checksums and reproducible SBOM evidence.
6. Publish only those verified bytes through the protected trusted-publishing workflow, without exposing credentials or bypassing an environment approval.
7. Create GitHub Release **TrustWeave 0.2.1** only after the tag, publication result, release notes, artifacts, and hashes have been independently verified.

No local build, draft note, prior tag, or passing subset of checks substitutes for this owner-controlled sequence.

## E. Rollback and preserved audit procedure

If a defect is discovered before publication, stop the sequence and prepare a corrective PR. Never rewrite shared history, move a tag, overwrite an artifact, or misrepresent an unpublished audit tag as a release.

| Situation | Required owner response |
| --- | --- |
| Defect before merge | Keep the PR unmerged; fix and re-run every gate. |
| Defect after merge but before `v0.2.1` | Stop release work; open a corrective PR; do not tag or publish. |
| Defect after a tag but before publication | Leave the tag immutable and unpublished; document the blocker; issue a new corrected version only under owner policy. |
| Defect after publication | Stop distribution, assess scope, preserve evidence, consider the authorized registry process, and publish a verified corrective version rather than replacing bytes or moving a tag. |

## F. Final release record

Record the final values below in the owner release issue, approved PR description, or release record.

| Record | Value |
| --- | --- |
| Corrective PR | PR URL and number |
| Final PR head | Full SHA |
| Merge SHA | Full SHA after owner merge |
| Version contract | Source, wheel, and import-visible version evidence for `0.2.1` |
| Mutation result | Generated / killed / survived / exact parity result |
| Local quality command | Timestamped output or archived log |
| Hosted checks | Exact names, conclusions, and URLs |
| Tag | Annotated `v0.2.1` and target SHA, if owner created one |
| Artifact hashes | SHA-256 for each approved wheel, sdist, and SBOM |
| Publication decision | Not published / PyPI, with owner authorization reference |
| Preserved 0.2.0 audit tag | `v0.2.0` at `7232fe3a23d92f50a693903c0a6b7cb92d0a1426`; never published and no GitHub Release |
| Rollback contact | Maintainer or security route used if needed |

Until this record is complete, treat `0.2.1` as a pre-release preparation target rather than a completed public release.
