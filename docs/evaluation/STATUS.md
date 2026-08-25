# TrustWeave Evaluation Status Ledger

This ledger prevents planned evaluation infrastructure from being presented as completed external validation. A status changes only when the linked evidence exists, has been reviewed by a human maintainer, and is safe to disclose.

| Evidence area | Status | Evidence required to advance | Current public claim allowed |
|---|---|---|---|
| Evaluation charter | **Prepared** | Versioned charter reviewed by human authors. | The project has a documented evaluation design. |
| Reviewer protocol | **Prepared** | Versioned protocol and feedback form reviewed by human authors. | The project has a protocol for future independent review. |
| Data-minimization policy | **Prepared** | Versioned policy and disclosure route reviewed by maintainers. | The planned study accepts only safe, synthetic inputs. |
| Synthetic evaluation corpus | **Planned in this pull request** | Versioned fixtures, manifest, runner, and deterministic verification. | No corpus result claim until the implementation is merged and verified. |
| Declaration-consistency benchmark | **Planned in this pull request** | Versioned static framework descriptors, manifests, raw exact-label comparator, explicit declared-reconciliation records, deterministic verification, and explicit limits. | Prepared synthetic consistency fixture only; no source-completeness, runtime-discovery, semantic-equivalence, or security-efficacy claim. |
| Independent reviewer recruitment | **Not yet collected** | Consent-aware invitation and completed reviewer ledger. | No claim of external review or community adoption. |
| Independent reviewer responses | **Not yet collected** | Consented responses, independence checks, protocol version, and analysis record. | No usability, clarity, or decision-support result. |
| Sanitized pilot | **Not yet collected** | Owner-approved pilot pack, consent/authorization record, and result ledger. | No real-world decision-support or pilot claim. |
| Comparative benchmark | **Not yet collected** | Predefined comparator, corpus, method, result record, and limitations. | No superiority, coverage, or performance comparison claim. |
| DOI or institutional archive | **Not yet collected** | Durable archive URL, manifest, checksums, and human approval. | No claim of durable archival preservation. |
| External method review | **Not yet collected** | Review record and public response log where consented. | No claim of third-party validation. |
| Research-paper outcome revision | **Not yet collected** | Human-reviewed evidence cutoff and updated claim–evidence matrix. | The paper remains an artifact-centered technical report/preprint. |

## Rules for updates

A status update must include the relevant tag or commit, date, evidence owner, and linked record. The update must preserve previous status history when it affects a paper or public report. A maintainer must never replace “not yet collected” with an inferred outcome, private conversation, or unverified testimonial.

## Current scope statement

TrustWeave `0.3.0` has verified release, package-provenance, and local assurance evidence. It does not yet have documented independent reviewer outcomes, pilots, adoption evidence, benchmark comparisons, or a durable research archive.
