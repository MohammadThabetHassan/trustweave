# ADR-0005: Package Release Provenance Boundary

## Status

Accepted as the design and verification policy applied to TrustWeave `0.3.0` and retained for future package releases. The exact `0.3.0` TestPyPI and PyPI wheels passed the policy’s consumer verification; [Release Evidence 0.3.0](RELEASE_EVIDENCE_0.3.0.md) records that limited observation. It does **not** assert authenticated package provenance for releases published before the policy was implemented or for any future file without its own verification.

## Context

TrustWeave produces unsigned local hash-linked attestations through `trustweave attest`. Those statements establish only internal consistency among supplied local artifact bytes and stable payloads; they do not authenticate an issuer, publish a transparency-log record, or prove the origin of a package downloaded from an index.

TrustWeave already uses PyPI Trusted Publishing through separate build and OIDC publish jobs. The official PyPA publishing action can generate and upload PEP 740-compatible attestations for each distribution by default when used with Trusted Publishing. PyPI documents a consumer verification procedure that retrieves an index-hosted provenance object and verifies a selected distribution against an expected repository identity.[1] [2]

The repository previously set `attestations: false` deliberately while no verified consumer procedure, identity policy, retention rule, or release-owner commitment existed. The project must not replace that explicit non-claim with vague “signed” terminology or conflate it with TrustWeave’s local evidence statements.

## Decision

The release assurance model has two explicitly separate layers.

| Layer | Subject | Current meaning | What it does not establish |
| --- | --- | --- | --- |
| **Local TrustWeave evidence** | A supplied manifest, policy, scenario result, local review artifact, and source revision | Internal hash-linked consistency for local evidence. | Signer identity, external provenance, deployment behavior, or runtime security. |
| **PyPI package provenance** | A wheel or source distribution uploaded through the reviewed release workflow | Cryptographically verifiable published-package provenance when the official PyPI mechanism is enabled and the observed artifact passes consumer verification. | That package code is defect-free, that a deployment is safe, or that an agent runtime is secure. |

TrustWeave used the official PyPI Trusted Publishing attestation path for the `0.3.0` release rather than adding custom local signing, DSSE commands, or a runtime provenance dependency. The same strictly staged procedure remains required for every future release:

1. Revalidate the official PyPI and GitHub documentation immediately before workflow modification, including action behavior, trusted-publisher identity requirements, expected permissions, and the consumer verification command.[1] [2] [3]
2. Review and SHA-pin every workflow action used by the changed publishing path. The release build job remains separate from the OIDC publish job.
3. Enable the official PyPI attestation behavior in the **TestPyPI** workflow first. No unsupported workflow permission or identity claim will be added merely because it appears in a third-party example.
4. Publish only a new, owner-authorized annotated TestPyPI release candidate. Record its exact wheel URL, SHA-256 digest, version, tag, workflow run, and expected repository identity.
5. From a fresh environment, install the exact TestPyPI version, download the exact wheel with its original filename, retrieve the matching TestPyPI Integrity API provenance object, and verify it against `https://github.com/MohammadThabetHassan/trustweave` using the official verifier’s local-file/provenance mode. A mismatch, missing provenance object, unexpected issuer/workflow identity, or verification error blocks production publication.
6. Enable the same reviewed behavior for the owner-authorized PyPI release only after TestPyPI verification succeeds. Repeat clean installation and consumer verification from the public PyPI artifact.
7. Update public documentation, release notes, and citation wording only after observed verification succeeds. If any stage fails, retain the existing explicit non-claim and publish a new fixed version only when release immutability requires it.

The expected identity policy is intentionally narrow: verification must bind the published distribution to the `https://github.com/MohammadThabetHassan/trustweave` repository and the reviewed trusted-publishing workflow that produced the exact tagged release. The exact workflow and environment details are release evidence to be checked, not assumptions to be inferred from a local configuration file.

## Consequences

This decision keeps TrustWeave’s core package free of a signing or network dependency and preserves the local-only behavior of every end-user command. Provenance verification belongs to the maintainer-controlled release procedure and reads public release metadata only when a maintainer explicitly invokes it.

The decision adds release-process obligations: a TestPyPI rehearsal, a clean consumer verification, a retained verification record, and an honest fallback if the provider flow changes. The repository may accurately claim authenticated **package** provenance only for a release whose published artifact has passed the documented procedure. It may not claim a SLSA level, complete supply-chain security, runtime protection, or external certification unless separate evidence is added.

## References

[1]: https://docs.pypi.org/attestations/producing-attestations/ "PyPI: Producing attestations"
[2]: https://docs.pypi.org/attestations/consuming-attestations/ "PyPI: Consuming attestations"
[3]: https://packaging.python.org/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/ "Python Packaging User Guide: Publishing package distribution releases using GitHub Actions CI/CD workflows"
[4]: https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds "GitHub Docs: Using artifact attestations to establish provenance for builds"
