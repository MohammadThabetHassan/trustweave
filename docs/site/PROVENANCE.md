# Provenance Design

## Current behavior

TrustWeave emits **unsigned local hash-linked evidence**. A local attestation can verify stable payload relationships and, when referenced files are supplied, exact local bytes. The result is an internally checkable local integrity statement. It is not a signature, identity assertion, transparency-log inclusion proof, DSSE envelope, SLSA level, or runtime-security claim.

## Deferred authenticated-provenance design

A future extension may add separately approved support for DSSE-wrapped statements and Sigstore signing. It must remain optional, must not alter unsigned local evidence, and must never perform signing, upload, publication, or identity retrieval without explicit owner authorization.

| Layer | Potential evidence | It still does not establish |
|---|---|---|
| Local hash consistency | Canonical payload relationships | Signer identity, source origin, or runtime security. |
| Exact-file verification | Referenced local artifact bytes | Who created a file or whether it was deployed. |
| Signature verification | A DSSE signature over explicit payload bytes | Authorization or a security result. |
| Identity verification | An explicit certificate identity and issuer policy | That the identity is authorized for every use. |
| Transparency-log inclusion | A Rekor inclusion proof and integrated time | A SLSA level, deployment state, or runtime behavior. |

## Preconditions for any live signing

Before adding an authenticated-provenance operation, the owner must approve the identity policy, issuer, workflow, dependency set, retention policy, and disclosure boundary. The implementation should use synthetic fixtures only, isolate signing to a least-privilege job, prohibit untrusted pull-request signing, and independently verify payload, signature, identity policy, and inclusion evidence before publishing a claim.

> No DSSE or Sigstore dependency, network operation, signing action, upload, publication, or release is introduced by this design documentation.

The authoritative design record and checklist are maintained in the [repository provenance design](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/PROVENANCE_DESIGN.md).
