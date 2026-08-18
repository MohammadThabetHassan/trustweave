# Owner Release Checklist: TrustWeave 0.2.0

> **Owner control:** This checklist is for the repository owner after review. It does not authorize an agent or contributor to merge, tag, sign, publish, create a GitHub Release, alter branch protection, or change release settings. Complete each gate in order and record the exact reviewed SHA.

## A. Pre-merge acceptance gate

| Gate | Owner evidence required | Status to record |
| --- | --- | --- |
| Correct branch | PR #17 targets `main`; no direct commit was made to `main`. | Head SHA and PR URL. |
| Semantic compatibility | Legacy v1alpha1 and current v1alpha2 validation tests pass; compatibility behavior is documented. | Test run link or log. |
| Mutation threshold | The twelve-module run is at least 95% killed. | Generated, killed, survived, and score. |
| Survivor triage | Exact survivor ID parity holds; `untriaged_count == 0`; `needs_regression == 0`; every equivalent/defensive record has a rationale. | Hosted mutation evidence artifact. |
| Security defects | No known P0 or P1 defect remains. | Review note and issue references. |
| Documentation | Configuration names, fourteen stages, release notes, migration guide, limitations, and version metadata are current. | Reviewed changed paths. |
| Local checks | Formatter, lint, types, Bandit, tests, and repository reality check all pass. | Exact local command output. |
| Hosted checks | All required checks are green on the exact final head SHA. | Check names and URLs. |

Do **not** approve merge readiness while any gate is incomplete. At the time this checklist was prepared, the numeric mutation threshold had been reached but the final inventory still contained unresolved `needs_regression` classifications; that is an explicit blocker until eliminated.

## B. Required final verification commands

Run from a clean checkout of the approved PR head SHA.

```bash
ruff format --check .
ruff check .
mypy src
bandit -r src/trustweave -q
pytest
python3 scripts/reality_check.py

rm -rf mutants .mutmut-cache
mutmut run
mutmut results
```

For reproducible staged-CI evidence, run two fixed-provenance executions into separate directories and compare every emitted byte:

```bash
trustweave --generated-at 2026-08-18T00:00:00+00:00 \
  ci --config trustweave.toml --source-revision owner-release-check --quiet
```

Follow the repository’s recorded reproducibility procedure in [REPRODUCIBILITY.md](REPRODUCIBILITY.md) for the two-directory comparison. Verify that no temporary staging path is present in emitted artifacts.

## C. Artifact verification after an owner-authorized release build

Only after all pre-merge and hosted gates are green, verify the distribution artifacts before any authorized publication:

```bash
python -m build
python -m pip install --force-reinstall dist/trustweave-0.2.0-py3-none-any.whl
python -c "import trustweave; print(trustweave.__version__)"
python -m pip check
```

Confirm that the wheel’s metadata version, import-visible `trustweave.__version__`, changelog heading, citation metadata, and release notes all identify `0.2.0`. Then validate a clean local workflow using installed code, strict configuration, and fixed provenance. Inspect the wheel contents and generated SBOM or audit evidence required by the repository’s release workflow before any registry action.

## D. Owner-authorized merge and release sequence

After the acceptance table is entirely green, the owner may choose to perform the following actions manually, subject to repository policy:

1. Merge the reviewed PR using the approved method and record the resulting `main` SHA.
2. Re-run or confirm required hosted checks on the merge result.
3. Create an annotated `v0.2.0` tag only on that verified SHA.
4. Build, inspect, and verify artifacts from the tag.
5. Sign or publish only if separately authorized and only through the least-privilege release workflow.
6. Create a GitHub Release only after the tag, artifacts, release notes, and publication status have been independently verified.

No contributor should substitute a local build, a draft note, or a passing subset of checks for this owner-controlled sequence.

## E. Rollback and yank procedure

If an issue is discovered before publication, stop the sequence, keep the tag and release unpublished, document the blocker, and prepare a corrective pull request. Do not rewrite shared history or alter existing evidence.

If an issue is discovered after authorized publication, the owner should immediately stop further publication, assess scope and security impact, communicate through the appropriate security or release channel, and use the authorized registry’s yank or removal process for the affected version if policy permits. Preserve the released artifact, tag, checks, and incident evidence. Publish a corrected version rather than replacing artifact bytes or moving a release tag.

| Situation | Required owner response |
| --- | --- |
| Defect before merge | Keep PR unmerged; fix and re-run every gate. |
| Defect after merge but before tag/publication | Stop release work; open a corrective PR; do not tag or publish. |
| Defect after tag but before publication | Leave the tag intact if policy requires auditability; do not publish it; issue a corrected tag only under owner policy. |
| Defect after publication | Stop distribution, consider registry yank, document impact, preserve evidence, and release a verified corrective version. |

## F. Final release record

Record the final values below in the owner’s release issue, approved PR description, or release record.

| Record | Value |
| --- | --- |
| Approved PR | PR URL and number |
| Final PR head | Full SHA |
| Merge SHA | Full SHA, after owner merge |
| Mutation result | Generated / killed / survived / exact parity result |
| Local quality command | Timestamped output or archived log |
| Hosted checks | Exact names, conclusion, and URLs |
| Tag | Annotated tag and target SHA, if owner created one |
| Artifact hashes | SHA-256 for each approved wheel and source distribution |
| Publication decision | Not published / TestPyPI / PyPI, with owner authorization reference |
| Rollback contact | Maintainer or security route used if needed |

Until this record is complete, treat 0.2.0 as a pre-release preparation target rather than a completed release.
