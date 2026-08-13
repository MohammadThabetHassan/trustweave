# Optional Authenticated Provenance Design

## Current behavior

TrustWeave currently supports **unsigned local hash-linked evidence**. An attestation can verify stable payload relationships and, when supplied, exact local artifact bytes. This is local integrity evidence only. It is not a signature, identity assertion, transparency-log inclusion proof, DSSE envelope, SLSA level, or runtime-security claim.

## Deferred optional design

A future owner-authorized authenticated-provenance extension may add a separate optional dependency extra and explicit commands for DSSE-wrapped statements and Sigstore keyless signing. It must not alter the meaning or availability of current unsigned evidence.

| Verification layer | Potential future evidence | What it does not establish |
|---|---|---|
| Local hash consistency | Existing canonical-payload relationships | Signer identity, file origin, or runtime security. |
| Exact-file verification | Existing supplied artifact byte hashes | Who created the artifact or whether it was deployed. |
| Signature verification | DSSE signature over an explicit payload | The signer’s authorization or a runtime security result. |
| Identity verification | Explicit Sigstore certificate identity and issuer policy | That the artifact is safe or that the identity is authorized for every use. |
| Transparency-log inclusion | Rekor inclusion proof and integrated time | A SLSA level, deployment state, or runtime behavior. |

## Owner checklist before any live signing

1. Approve the exact identity policy, issuer, repository workflow, and disclosure boundary.
2. Approve the optional dependency set after dependency and license review.
3. Use synthetic fixtures only in tests; never record a real identity or private token.
4. Require a separate signing job with least privilege and no pull-request signing from untrusted forks.
5. Decide whether and where signed envelopes, certificates, and Rekor proofs are retained.
6. Verify the signed payload, signature, identity policy, and inclusion proof independently in CI before describing the result.
7. Document the distinction between a local attestation and authenticated provenance in release notes.
8. Obtain explicit authorization before signing, publishing, tagging, releasing, uploading, or enabling any external provenance service.

No DSSE or Sigstore library is installed by this design note, no network operation is introduced, and no signing, upload, publication, or release is performed.
