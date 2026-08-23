# TrustWeave 0.2.0 Unpublished Audit Checklist

> **Audit status:** `v0.2.0` is an annotated immutable tag at `7232fe3a23d92f50a693903c0a6b7cb92d0a1426`. It was never published to PyPI and has no GitHub Release. Do not move, delete, reuse, or publish from it. This document preserves its historical release evidence; use [OWNER_RELEASE_CHECKLIST_0.2.1.md](OWNER_RELEASE_CHECKLIST_0.2.1.md) for the corrected current target.
>
> **Historical-only warning:** The retained commands and sequence below describe the superseded 0.2.0 preparation record. Do not execute them or treat them as authorization for any current tag, build, publication, or GitHub Release.

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

rm -rf mutants .mutmut-cache
mutmut run
mutmut results
```

For reproducible staged-CI evidence, run the directly executable clean-checkout verifier. It creates two temporary run directories and a separate explicit temporary `trustweave.toml` in each directory; it never relies on or creates a repository-root configuration file.

```bash
python3 scripts/verify_release_reproducibility.py \
  --source-revision "$(git rev-parse HEAD)" \
  --generated-at 2026-08-19T00:00:00+00:00
```

The helper uses the tracked manifest, policy, scenarios, and safe-sanitized chain fixture; enables `scan`, `scenarios`, `policy_review`, `chain_review`, `sarif`, `attestation`, `report`, and `summary`; writes only relative local artifact paths; compares all emitted bytes; rejects temporary, checkout, and machine-specific path leakage; verifies each v1alpha3 attestation against its supplied bundle and test-results files; cleans temporary directories; and confirms that the working tree remains unchanged. Follow [REPRODUCIBILITY.md](../REPRODUCIBILITY.md) for the complete scope and limits.

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

This historical record is complete only as an unpublished audit trail. Treat `0.2.1`, not `0.2.0`, as the current release-preparation target.
