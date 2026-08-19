# Research record: PyPI attestations and GitHub build provenance

**Reviewed:** 2026-08-19
**Purpose:** Design the TrustWeave 0.2.3 release-provenance gate without claiming authenticated provenance before it is observed and verified.

## Findings

PyPI supports attaching attestations to individual release files during upload. When the official `pypa/gh-action-pypi-publish` action is used with Trusted Publishing, PyPI documents that attestations are generated and uploaded by default. The Python Packaging User Guide states that this behavior applies from action version `v1.11.0` onward. TrustWeave currently uses the official action but explicitly disables attestations, so no earlier package release may be described as attested until a new release is published and independently checked.[1] [2]

PyPI exposes release-file attestations through its simple index and simple JSON APIs. Its documented `pypi-attestations verify pypi --repository <owner/repository> <wheel-url>` procedure checks the selected repository identity, retrieves the related provenance object, and cryptographically verifies the distribution file against its attestations.[3]

GitHub independently documents build-provenance attestations through `actions/attest`. A binary-attestation workflow requires least-privilege `contents: read`, `id-token: write`, and `attestations: write` permissions, then attests the built subject path. GitHub CLI verification can validate an artifact against an expected repository. This is distinct from PyPI package attestations and must not be represented as the same mechanism without explicit documented linkage.[4]

## TrustWeave implementation decision

TrustWeave will prefer the official PyPI Trusted Publishing attestation path for package-release provenance rather than adding custom local signing. The next release cycle must first enable and validate TestPyPI attestation generation, then perform a clean install and official provenance verification against the expected repository identity. Production PyPI attestation generation remains an owner-controlled release action after the TestPyPI verification is successful.

Until that observed validation exists, TrustWeave continues to make its current explicit non-claim about authenticated package provenance. Local `trustweave attest` evidence remains unsigned, local artifact-integrity evidence and must never be conflated with release-package provenance.

## Required pre-publication checks

| Check | Required observed evidence |
| --- | --- |
| Workflow behavior | The exact SHA-pinned publishing action accepts the attestation configuration and the TestPyPI workflow completes successfully. |
| Artifact identity | The TestPyPI wheel URL, filename, version, and SHA-256 correspond to the reviewed annotated tag. |
| Trusted identity | Official verification accepts only `MohammadThabetHassan/trustweave` for the published artifact. |
| Consumer verification | A fresh environment installs the exact package and performs the official provenance verification. |
| Public language | `docs/SUPPLY_CHAIN.md`, release notes, and project metadata are updated only after all prior rows pass. |

## References

[1]: https://docs.pypi.org/attestations/producing-attestations/ "PyPI: Producing attestations"
[2]: https://packaging.python.org/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/ "Python Packaging User Guide: Publishing package distribution releases using GitHub Actions CI/CD workflows"
[3]: https://docs.pypi.org/attestations/consuming-attestations/ "PyPI: Consuming attestations"
[4]: https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds "GitHub Docs: Using artifact attestations to establish provenance for builds"

## OpenSSF Scorecard evaluation

The official OpenSSF Scorecard action is available for public repositories and supports `push` and default-branch `schedule` triggers; pull-request and manual triggers are documented as experimental. Publishing Scorecard results requires `id-token: write` for the Scorecard job and imposes workflow restrictions intended to protect the integrity of published results. The action also publishes SARIF results to GitHub’s code-scanning surface and may retain uploaded debugging artifacts for a limited period.[5]

TrustWeave will not add a Scorecard badge during the initial assurance implementation. A separate review must first determine whether its scheduled/public-result behavior, code-scanning publication, allowed action list, permissions, artifact retention, and current direct-main policy are acceptable. If that review succeeds, Scorecard will run in an isolated, SHA-pinned, least-privilege workflow whose public report is verified before any README badge is added. Otherwise, the repository retains the existing non-claim.

[5]: https://github.com/ossf/scorecard-action "OpenSSF Scorecard Action"
