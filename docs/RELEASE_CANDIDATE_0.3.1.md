# TrustWeave 0.3.1 Release Candidate Record

## Status

**Prepared source candidate; not published.** This record is not a tag, GitHub Release, TestPyPI upload, PyPI upload, archive record, provenance verification, or owner authorization. The last observed public package release is `0.3.0`; its exact-file evidence remains in [Release Evidence 0.3.0](RELEASE_EVIDENCE_0.3.0.md).

The candidate source metadata declares `0.3.1`. The exact release-target SHA, annotated tag, artifact URLs, artifact hashes, workflow run URLs, package-index observations, clean-install outputs, and provenance-verifier results must be entered only after those events occur.

## Intended scope

| Area | Candidate change | Explicit limit |
|---|---|---|
| Evaluation foundations | Versioned governance, a twelve-case synthetic corpus, deterministic preflight, lifecycle controls, reviewer quickstart, and safe feedback/triage material. | Prepared infrastructure does not establish an independent review, pilot, benchmark, adoption result, or security efficacy. |
| Governance evidence | Owner-facing branch-protection decision record and claim-boundary checks. | Documentation does not prove a live GitHub setting; the owner must observe and record it. |
| External assessment readiness | Manual least-privilege Scorecard workflow retaining a short-lived Actions artifact with publication disabled. | No Scorecard run, score, badge, certification, public result, or remediation claim exists yet. |
| Reviewer and archive readiness | Offline synthetic reviewer packet and deterministic allowlisted local archive builder/verifier. | No reviewer is recruited, no response is collected, and no durable archive/DOI is created by these files. |
| Public package metadata | Durable README release references and source/public-release separation in the compatibility contract. | Source version `0.3.1` remains unpublished until the owner completes the release procedure. |

## Required pre-publication evidence

Run these commands on the exact intended source revision. Record the output location and SHA in an owner-approved release record only after each command succeeds.

```bash
ruff format --check .
ruff check .
mypy src
bandit -r src/trustweave -q
pytest -q
python scripts/run_evaluation_corpus.py --check
python scripts/run_evaluation_corpus.py --verify
python scripts/build_evaluation_artifact.py \
  --kind reviewer-packet \
  --revision "$(git rev-parse HEAD)" \
  --output-dir /tmp/trustweave-reviewer-packet
python scripts/build_evaluation_artifact.py \
  --verify-manifest /tmp/trustweave-reviewer-packet/evaluation-artifact-manifest.json
python scripts/verify_assurance_contracts.py
python scripts/verify_package_provenance_controls.py
python scripts/verify_golden_evidence.py
python scripts/verify_control_traceability.py
python scripts/verify_distribution_artifacts.py
python scripts/verify_release_reproducibility.py \
  --source-revision "$(git rev-parse HEAD)" \
  --generated-at 2026-08-22T00:00:00+00:00
python scripts/reality_check.py
mkdocs build --strict && rm -rf site
pip-audit -r requirements.txt
rm -rf dist && python -m build && twine check dist/*
```

The owner must then push the verified candidate commit and wait for all hosted checks on that exact SHA. A green local suite or hosted workflow does not authorize tagging, publishing, or release creation.

## Owner-authorized publication sequence

Only after explicit owner confirmation: create the annotated `v0.3.1` tag on the exact verified SHA; dispatch the TestPyPI workflow; clean-install and verify the exact TestPyPI artifact and its matching provenance; dispatch the PyPI workflow; clean-install and verify the exact PyPI artifact and its matching provenance; create the GitHub Release from the same tag; then add a new observed release-evidence record.

Never overwrite package files, move a release tag, reuse a failed version, or replace this candidate record with an observed-evidence claim. If any step fails, stop, inspect the exact evidence, and prepare a new verified candidate only when immutability rules require it.

## Candidate evidence ledger

| Evidence item | State | Observed value |
|---|---|---|
| Candidate source SHA | Pending final verified commit | Not yet recorded. |
| Hosted checks on candidate SHA | Pending push | Not yet recorded. |
| Annotated `v0.3.1` tag | Not authorized | Not created. |
| TestPyPI distribution | Not authorized | Not published. |
| TestPyPI clean-install/provenance verification | Not applicable before publication | Not recorded. |
| PyPI distribution | Not authorized | Not published. |
| PyPI clean-install/provenance verification | Not applicable before publication | Not recorded. |
| GitHub Release | Not authorized | Not created. |

## Claim boundary

Until the ledger contains observed evidence, permitted wording is: “TrustWeave source metadata is prepared as a `0.3.1` release candidate.” It is not permitted to say “TrustWeave 0.3.1 is released,” “published,” “verified,” “attested,” “archived,” “Scorecard assessed,” “independently reviewed,” or “secure.”
