# Evaluation Artifact Archive Readiness

## Purpose

This checklist prepares a disclosure-safe, reproducible TrustWeave evaluation artifact for a future technical report, preprint supplement, or durable archive. It does **not** create an archive, reserve a DOI, publish data, recruit reviewers, or authorize a release. Those actions remain owner-controlled and may occur only after human review.

> A directory is archive-ready only when every applicable item below has a linked, human-reviewed record. Do not represent this checklist, a local checksum, or a release workflow as an archive identifier, signature, independent validation, or tamper-proof guarantee.

## Candidate artifact scope

The default candidate is intentionally narrow and must contain only public, synthetic, repository-controlled material.

| Include only after review | Exclude categorically |
|---|---|
| Versioned corpus manifest, synthetic fixtures, and local runner. | Credentials, tokens, cookies, keys, or connection strings. |
| Reproduction instructions, corpus lifecycle policy, evaluation charter, reviewer protocol, status ledger, and limitations. | Production manifests, customer data, personal data, proprietary source, real traces, message content, tool arguments, live hosts, or target details. |
| Exact repository commit, package version, environment notes, command transcript, output checksums, and safe generated summaries. | Private reviewer communications, unconsented feedback, identity data, raw study responses, or inferred adoption claims. |
| Human-reviewed claim–evidence–limitation matrix and reproducibility appendix, if the authors approve them. | Any claim not supported by the included, disclosed evidence. |

## Readiness checklist

| Check | Required record | Owner decision |
|---|---|---|
| Exact source identity | Repository URL, immutable commit SHA, package version, corpus schema/version, and date recorded. | Confirm the selected commit is the intended evidence cutoff. |
| Reproduction result | `--check` and `--verify` command outputs plus SHA-256 values for retained summary files. | Confirm the commands were run in a clean, documented environment. |
| Scope review | File inventory reviewed against the include/exclude table. | Approve that every included file is public and disclosure-safe. |
| Licensing review | Repository license plus licenses/attributions for any included third-party material. | Confirm redistribution is permitted. |
| Data-minimization review | Link to the data-minimization policy and a documented empty-sensitive-data finding. | Approve that no sensitive or unauthorized material is present. |
| Claim review | Claim–evidence–limitation matrix reviewed against the selected artifact. | Approve that all public wording remains proportionate. |
| Human accountability | Named human maintainer/author review and date. | Approve any public upload, metadata, and author list. |
| Immutable packaging | File manifest with SHA-256 checksums and an archive filename/version. | Approve the exact bytes for upload. |
| Archive metadata | Draft title, authors, description, license, version, and related-repository URL. | Approve the metadata and chosen archive service. |
| Durable record | Actual public archive URL and identifier, if created. | Record only after the service has issued it. |

## Local evidence capture

Use the following commands from a clean checkout only after the owner has selected a candidate commit. They create local outputs for review; they do not upload or publish anything.

```bash
python scripts/run_evaluation_corpus.py --check
rm -rf /tmp/trustweave-archive-review
python scripts/run_evaluation_corpus.py --verify --output-dir /tmp/trustweave-archive-review
git rev-parse HEAD
python -c "import trustweave; print(trustweave.__version__)"
python --version
sha256sum /tmp/trustweave-archive-review/evaluation-corpus-summary.json
sha256sum /tmp/trustweave-archive-review/evaluation-corpus-summary.md

python scripts/build_evaluation_artifact.py \
  --kind technical-report-supplement \
  --revision "$(git rev-parse HEAD)" \
  --output-dir /tmp/trustweave-archive-package
python scripts/build_evaluation_artifact.py \
  --verify-manifest /tmp/trustweave-archive-package/evaluation-artifact-manifest.json
sha256sum /tmp/trustweave-archive-package/evaluation-artifact-manifest.json
sha256sum /tmp/trustweave-archive-package/trustweave-technical-report-supplement.zip
unzip -Z1 /tmp/trustweave-archive-package/trustweave-technical-report-supplement.zip
```

The artifact builder accepts only the checked-in allowlist, validates safe relative paths, rejects prohibited transient paths and credential-like content, records stable SHA-256 digests, and produces deterministic member ordering. It performs no network request, upload, archive-service action, model call, target interaction, or reviewer contact. The manifest verifier checks that the selected files still match the current approved repository bytes.

A maintainer may then prepare a file inventory and checksums for the selected public files. The inventory must be reviewed before it is packaged. Do not archive transient virtual environments, test caches, local logs, untracked files, or entire home directories.

## Required wording before an archive exists

Until an archive service has issued a durable public record and a human maintainer has reviewed it, use only this scope statement:

> TrustWeave has an archive-readiness checklist for a future synthetic evaluation artifact. A durable archive URL or DOI has not yet been recorded.

After an archive exists, record its exact URL, identifier, artifact version, repository commit, corpus version, package version, file manifest, and disclosure review in `docs/evaluation/STATUS.md`. Preserve prior status history and retain the original claim boundaries.
