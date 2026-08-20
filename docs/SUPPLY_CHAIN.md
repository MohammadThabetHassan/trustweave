# Supply-Chain Evidence Guide

## Scope

TrustWeave is a Python package with an intentionally empty core runtime dependency set. This guide describes controls implemented for the current public `0.3.0` package. The exact `0.3.0` TestPyPI and PyPI wheels passed the documented expected-repository provenance verification; that observed evidence is limited to those files and does not imply a certification, SLSA level, or OpenSSF badge.

## Implemented controls

| Control | Evidence and limit |
| --- | --- |
| Immutable workflow-action references | Every third-party action in `.github/workflows/` is pinned to a reviewed full commit SHA, with the source release label retained in a comment. The repository reality checker rejects mutable action tags. |
| Least-privilege CI | Quality and compatibility workflows request `contents: read`. The PyPI and TestPyPI publish jobs request `id-token: write` only in their isolated OIDC upload jobs. |
| Trusted publishing | Separate manual TestPyPI and PyPI workflows build and validate distributions before isolated OIDC publication. No stored PyPI upload token is used. |
| Reproducible wheel evidence | CI compares two fixed-epoch wheel builds from the same working tree. This is wheel reproducibility evidence, not a claim that every distribution format is byte reproducible. |
| SBOM evidence | CI generates a reproducible CycloneDX SBOM for the verified Python environment and project metadata. |
| Dependency review | Pull requests receive dependency-review checks. The core runtime dependency set is empty, so a clean runtime audit does not describe the entire developer workstation. |
| Package validation | CI builds, validates metadata, and invokes the installed wheel in an isolated environment. TestPyPI and production PyPI installations were separately validated in fresh environments for `0.3.0`, including console and module CLI entry points. |

## Deliberately not claimed

For the exact `0.3.0` TestPyPI and PyPI wheels, the PyPI Integrity API provenance objects were verified against the expected repository `https://github.com/MohammadThabetHassan/trustweave`; the observed commands, file URLs, hashes, workflows, and clean-install checks are recorded in [Release Evidence 0.3.0](RELEASE_EVIDENCE_0.3.0.md). This is an authenticated package-provenance claim only for those exact published files. TrustWeave does not claim SLSA provenance, a general transparency-log security property, an OpenSSF Scorecard result, or an OpenSSF Best Practices badge. [ADR-0005](ADR-0005-PACKAGE-RELEASE-PROVENANCE.md) and [Package Release Provenance](PACKAGE_PROVENANCE.md) define the TestPyPI-first procedure. Unsigned local `trustweave attest` evidence remains distinct local integrity evidence and is not authenticated package provenance.

Repository-native secret scanning, push protection, Dependabot security updates, and code-scanning upload are maintainer configuration decisions. They can create alerts, block pushes, or open pull requests, so they are not silently enabled by this document or by the default CI workflow. The maturity plan records them as proposed controls requiring a maintainer decision.

## Review procedure

Before accepting a workflow-action update, a maintainer must review the upstream release, resolve the exact commit SHA, preserve the readable release comment, run the repository reality check, and obtain the normal CI result on the proposed commit. Dependency-update automation, if authorized later, must propose reviewable updates and must not auto-merge them.

## References

[1]: https://scorecard.dev/ "OpenSSF Scorecard"
[2]: https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates "GitHub Docs: Dependabot security updates"
[3]: https://docs.github.com/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql "GitHub Docs: CodeQL code scanning"
[4]: https://docs.pypi.org/trusted-publishers/ "PyPI Trusted Publishers"
