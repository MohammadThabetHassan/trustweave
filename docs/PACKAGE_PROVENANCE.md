# Package Release Provenance

## Current state

TrustWeave’s **0.2.3 release workflows are configured to request PyPI project attestations** through the official pinned Trusted Publishing action for both TestPyPI and PyPI. This configuration is a release control, not observed release evidence.

> No TrustWeave release is described as having authenticated package provenance until a release-specific TestPyPI or PyPI artifact has been published from its reviewed immutable tag and independently verified against `MohammadThabetHassan/trustweave`.

Local `trustweave attest` output remains unsigned local integrity evidence. It binds supplied local evidence payloads and may detect selected local-file changes, but it does not identify a publisher, authenticate a package release, or replace PyPI project attestations. GitHub build-provenance attestation is a distinct mechanism and is not enabled or claimed by this release control.

## Release-gate procedure

The TestPyPI flow is the required first observation for a release candidate.

| Gate | Required evidence before proceeding |
| --- | --- |
| Immutable target | An annotated version tag identifies the reviewed release commit. |
| Workflow control | The SHA-pinned TestPyPI trusted-publishing workflow completes with `attestations: true`. |
| Package identity | The published file URL, filename, package version, and SHA-256 are recorded. |
| Trusted identity | Official PyPI-attestations verification accepts **only** `MohammadThabetHassan/trustweave` for that exact file URL. |
| Consumer path | A fresh environment installs the exact candidate and validates `trustweave --version`, `python -m trustweave --version`, and packaged schema resources. |
| Production promotion | The PyPI workflow runs only after the TestPyPI record satisfies every preceding gate. |

The release operator installs the official verifier in a temporary clean environment, obtains the exact published wheel URL from the TestPyPI or PyPI simple index, and verifies it against the expected repository:

```bash
python -m pip install --upgrade pypi-attestations
pypi-attestations verify pypi \
  --repository MohammadThabetHassan/trustweave \
  https://files.pythonhosted.org/packages/.../trustweave-VERSION-py3-none-any.whl
```

Use the actual index-hosted artifact URL; do not substitute a local build, a copied file, a mutable branch URL, or a generic project page. Preserve the verifier output, package URL, SHA-256, tag, workflow run URL, and clean-install result in the release record before changing present-tense provenance language.

## Control and sources

The exact workflow requirements are machine-checked by [`docs/contracts/package-provenance-v1.json`](contracts/package-provenance-v1.json). The design decision and provider research remain in [ADR-0005](ADR-0005-PACKAGE-RELEASE-PROVENANCE.md) and the [2026-08 research record](research/2026-08-pypi-attestations-and-github-provenance.md). The procedure follows the provider documentation for producing and consuming PyPI attestations.[1] [2]

## Limits

A passing provider-verification result applies to the exact selected distribution file and expected repository identity. It does not establish that every local file, system, dependency, artifact copy, user download, agent runtime, or source declaration is secure. Attestation publication and verification are release operations; TrustWeave’s package runtime remains local-only and non-executing.

## References

[1]: https://docs.pypi.org/attestations/producing-attestations/ "PyPI: Producing attestations"
[2]: https://docs.pypi.org/attestations/consuming-attestations/ "PyPI: Consuming attestations"
