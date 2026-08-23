# Package Release Provenance

## Current state

TrustWeave’s **0.3.0 release workflows requested PyPI project attestations** through the official pinned Trusted Publishing action for both TestPyPI and PyPI. The exact published wheels were independently verified against the expected repository; the complete observed record is [Release Evidence 0.3.0](RELEASE_EVIDENCE_0.3.0.md).

> The authenticated package-provenance claim applies only to the exact `0.3.0` TestPyPI and PyPI wheels documented in the release-evidence record. It is not a claim about future releases, local builds, arbitrary copies, or deployed systems.

Local `trustweave attest` output remains unsigned local integrity evidence. It binds supplied local evidence payloads and may detect selected local-file changes, but it does not identify a publisher, authenticate a package release, or replace PyPI project attestations. GitHub build-provenance attestation is a distinct mechanism and is not enabled or claimed by this release control.

## Release-gate procedure

The TestPyPI flow is the required first observation for a release candidate.

| Gate | Required evidence before proceeding |
| --- | --- |
| Immutable target | An annotated version tag identifies the reviewed release commit. |
| Workflow control | The SHA-pinned TestPyPI trusted-publishing workflow completes with `attestations: true`. |
| Package identity | The published file URL, filename, package version, and SHA-256 are recorded. |
| Trusted identity | Official PyPI-attestations verification accepts only `https://github.com/MohammadThabetHassan/trustweave` for the exact selected distribution and provenance object. |
| Consumer path | A fresh environment installs the exact candidate and validates `trustweave --version`, `python -m trustweave --version`, and packaged schema resources. |
| Production promotion | The PyPI workflow runs only after the TestPyPI record satisfies every preceding gate. |

The release operator installs the official verifier in a temporary clean environment and verifies production-PyPI wheels directly against the expected repository:

```bash
python -m pip install --upgrade pypi-attestations
pypi-attestations verify pypi \
  --repository https://github.com/MohammadThabetHassan/trustweave \
  https://files.pythonhosted.org/packages/.../trustweave-VERSION-py3-none-any.whl
```

The verifier’s direct URL mode accepts the production `files.pythonhosted.org` host. For TestPyPI, download the exact wheel with its original filename and retrieve the matching TestPyPI Integrity API provenance object; then use the supported local-file mode:

```bash
pypi-attestations verify pypi \
  --repository https://github.com/MohammadThabetHassan/trustweave \
  --provenance-file trustweave-VERSION-py3-none-any.whl.provenance \
  trustweave-VERSION-py3-none-any.whl
```

Do not substitute a local build, a modified copy, a mutable branch URL, or a generic project page. Preserve the verifier output, package URL, SHA-256, tag, workflow run URL, Integrity API provenance object, and clean-install result in the release record before changing present-tense provenance language.

## Observed 0.3.0 evidence

The `v0.3.0` tag targets `30308f47e84025315de2083047039e7efe0fd0ae`. TestPyPI and PyPI trusted-publishing workflows completed successfully, fresh environments installed `trustweave==0.3.0` from both indexes, and expected-repository verification returned `OK` for the exact wheel from each index. See [Release Evidence 0.3.0](RELEASE_EVIDENCE_0.3.0.md) for immutable URLs, hashes, workflow runs, and commands.

## Control and sources

The exact workflow requirements are machine-checked by [`docs/contracts/package-provenance-v1.json`](contracts/package-provenance-v1.json). The design decision and provider research remain in [ADR-0005](adr/ADR-0005-PACKAGE-RELEASE-PROVENANCE.md) and the [2026-08 research record](research/2026-08-pypi-attestations-and-github-provenance.md). The procedure follows the provider documentation for producing and consuming PyPI attestations.[1] [2]

## Limits

A passing provider-verification result applies to the exact selected distribution file and expected repository identity. It does not establish that every local file, system, dependency, artifact copy, user download, agent runtime, or source declaration is secure. Attestation publication and verification are release operations; TrustWeave’s package runtime remains local-only and non-executing.

## References

[1]: https://docs.pypi.org/attestations/producing-attestations/ "PyPI: Producing attestations"
[2]: https://docs.pypi.org/attestations/consuming-attestations/ "PyPI: Consuming attestations"
