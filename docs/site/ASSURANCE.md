# Assurance controls

TrustWeave’s assurance records describe **reviewable repository and package controls** for the local evidence tool. They do not convert TrustWeave into a runtime enforcement product, a hosted service, or a certification claim.

| Control | What is checked | What it does not establish |
| --- | --- | --- |
| [Compatibility contract](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/COMPATIBILITY.md) | Supported Python versions, top-level CLI surface, documented exit statuses, current artifact writers, bounded readers, and deprecation policy. | Backward compatibility for undocumented inputs or a future major version. |
| [Golden deterministic evidence](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/GOLDEN_EVIDENCE.md) | Six synthetic local case families, canonical output digests, schema validity, output privacy markers, and explicit snapshot updates. | Completeness for arbitrary inputs, live targets, or runtime behavior. |
| [Control traceability](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/CONTROL_TRACEABILITY.md) | Links from stated declaration-layer threats to implementation paths, regression tests, evidence, maintenance triggers, and residual limits. | Full live-system threat coverage or external certification. |
| [Local resource bounds](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/RESOURCE_BOUNDS.md) | Input size, nesting, item count, declared-chain budgets, and SARIF result cardinality. | A hosted-service performance guarantee or runtime availability. |
| [Distribution assurance](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/DISTRIBUTION_ASSURANCE.md) | Temporary wheel/source archive inspection and installation in fresh local virtual environments. | Registry publication, third-party artifact identity, or cross-platform byte reproducibility. |
| [Package release provenance](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/PACKAGE_PROVENANCE.md) | Trusted-publishing workflows request PyPI project attestations; the exact `0.3.0` TestPyPI and PyPI wheels passed expected-repository verification. | Authenticated provenance for any file other than the exact verified `0.3.0` distributions, or a security certification. |

> **Current release state:** [`0.3.0`](https://pypi.org/project/trustweave/0.3.0/) is the current public package release. Its exact TestPyPI and PyPI wheels passed clean-install and expected-repository provenance verification; see the [release evidence record](RELEASE_EVIDENCE_0.3.0.md). This observed evidence is limited to those exact files.

Run the local assurance checks from a source checkout:

```bash
python scripts/verify_assurance_contracts.py
python scripts/verify_golden_evidence.py
python scripts/verify_control_traceability.py
python scripts/verify_distribution_artifacts.py
python scripts/verify_package_provenance_controls.py
```

The repository reality gate runs these controls as part of its broader check. The golden-evidence and traceability commands are check-only by default. Package provenance verification is a release operation that applies only after an exact TestPyPI or PyPI artifact exists and its expected-repository verification has been recorded.
