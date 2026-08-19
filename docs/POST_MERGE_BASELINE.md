# Post-Merge Correctness Baseline

## Scope and boundary

This record captures the state of `main` immediately after [PR #16](https://github.com/MohammadThabetHassan/trustweave/pull/16) was merged and before the final correctness follow-up work began. It is baseline evidence only. It does not assert that the repository meets the final 9.8 acceptance gate, and it does not authorize a merge, tag, signing operation, or package publication.

| Field | Recorded value |
| --- | --- |
| Baseline commit | `de9ffb33efd92ebe53605d48b1405d2dd98d05e7` |
| Baseline branch | `origin/main` |
| Merged predecessor | PR #16, `fix: complete TrustWeave 0.2.0 release hardening` |
| Python | `3.12.3` |
| Package version | Historical baseline: `0.2.0` source-prepared; 0.1.1 was the published PyPI version at that point. The later `v0.2.0` tag is immutable unpublished audit evidence; corrected current target is `0.2.1`. |

## Executed baseline controls

The following commands were executed against the baseline checkout after installing the declared development and release-verification tools:

```bash
ruff format --check .
ruff check .
mypy src
bandit -r src/trustweave -q
pytest
python scripts/reality_check.py
python -m build
twine check dist/*
```

All commands above passed at this historical baseline. The test suite reported **311 passed** with **95.09%** branch coverage against its enforced 95% threshold. The repository-reality check passed. The build produced and `twine check` accepted baseline `trustweave-0.2.0-py3-none-any.whl` and `trustweave-0.2.0.tar.gz` evidence; those files were not published. Current release verification must use the corrected `0.2.1` target.

| Tool | Version |
| --- | --- |
| pytest | 9.1.1 |
| pytest-cov | 7.1.0 |
| Hypothesis | 6.165.5 |
| jsonschema | 4.26.0 |
| Ruff | 0.16.2 |
| mypy | 2.3.0 |
| mutmut | 3.7.0 |
| Bandit | 1.9.4 |
| build | 1.5.0 |
| pip-audit | 2.10.1 |
| twine | 7.0.0 |
| mkdocs-material | 9.7.7 |
| PyYAML | 6.0.3 |

## Baseline public-schema catalog

The package advertised the following 16 schema resources at baseline:

```text
agent-manifest.schema.json
agent-security-bundle-v1alpha1.schema.json
attestation-v1alpha3.schema.json
chain-manifest-v1alpha1.schema.json
chain-review-v1alpha1.schema.json
ci-summary-v1alpha1.schema.json
finding-v1alpha1.schema.json
mcp-profile.schema.json
policy-explanation-v1alpha1.schema.json
policy-v1alpha2.schema.json
policy.schema.json
risk-baseline.schema.json
risk-review.schema.json
risk-suppressions.schema.json
scenario-pack-v1alpha1.schema.json
trace.schema.json
```

A complete fixed-provenance staged-CI baseline run emitted these 10 artifacts: `agent-security-bundle.json`, `attestation.json`, `chain-review.json`, `chain-review.md`, `ci-summary.json`, `policy-review.json`, `policy-review.md`, `report.md`, `security-test-results.json`, and `trustweave.sarif`.

## Baseline mutation diagnostic

The configured Linux mutation diagnostic covered `engine.py`, `models.py`, `policy_predicates.py`, and `risk.py`. Its executed baseline run generated **2,339** mutants, killed **1,911**, left **428** surviving, and recorded zero untested, timed-out, or suspicious mutants, for an **81.70%** killed score. That measurement is below the requested 90% high-risk target and is the starting point for this correctness follow-up; it is not a full-package mutation claim.

## Known correctness follow-up scope

The follow-up PR begins from this passing baseline to reproduce and address the supplied edge-case defects in risk deduplication, severity-aware decision applicability, configured risk paths, threshold semantics, validate-stage behavior, policy binding, runtime/schema parity, generated schemas, documentation, and high-risk mutation quality. Each claimed correction must be regression-tested and re-verified on the final PR head.
