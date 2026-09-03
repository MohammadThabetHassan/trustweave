# Current research-evidence decision record

## Decision status

**Decision: keep the existing manuscript as a historical `0.2.3` technical-report draft until the human authors either complete a full evidence refresh or explicitly publish it with historical framing.**

The current manuscript is not a current-project evaluation. It reports an artifact-centered study tied to older `0.2.3` evidence, an older environment, and an earlier repository state. A current-project external outcome remains not established. Later repository work—including the `0.3.1` source candidate, the declaration-consistency benchmark, the demo gallery, and the documentation-polish merges—must not be silently inserted into those historical results.

> A current source checkout can be more mature than the version evaluated by a paper. That does not retroactively update the paper’s methods, results, or claims.

## Verified present boundary

| Area | Current safe statement | Not established |
|---|---|---|
| Product | TrustWeave is a local, deterministic, non-executing evidence tool for supplied declarations and pre-recorded metadata. | Runtime agent security, prompt-injection prevention, live MCP behavior, or deployment enforcement. |
| Current source | The repository contains expanded evidence-readiness material, including declaration-consistency controls and reviewer preparation. | That external reviewers have used it or that the controls predict production outcomes. |
| Public release | `0.3.0` is the latest observed public package/release record. | A public `0.3.1` release, until the owner-authorized publication sequence is completed and exact artifacts are verified. |
| External evidence | Independent reproduction, pilot, comparative benchmark, adoption, and archive/DOI remain uncollected unless a versioned record says otherwise. | Any claim of independent validation, efficacy, adoption, certification, or security improvement. |

## Two acceptable manuscript paths

### Path A — Historical technical report

Keep the manuscript’s artifact version, evidence cutoff, environment, release identity, and claim matrix visibly tied to `0.2.3`. Add a short “historical evaluation” note near the abstract, introduction, evaluation method, and conclusion. Do not use current repository metrics as if they were part of the historical study. This is the lowest-risk path if no new study is being conducted.

### Path B — Full current refresh

Create a new evidence cutoff and refresh the manuscript end to end. At minimum, update the artifact version and commit identity; re-run the compatibility, corpus, coverage, mutation, traceability, provenance, distribution, and documentation checks; update figures, tables, commands, and output hashes; reconcile every claim in the matrix; and rewrite the limitations around the current benchmark scope. A partial replacement of version labels is not a valid refresh.

A full refresh must still state that the evaluation is artifact-centered unless independent participants, real-framework cases, or comparative outcomes are actually collected. Current repository tests can support implementation and reproducibility claims; they cannot support claims about user benefit, runtime security, or adoption.

## Current claim-control checklist

Before a manuscript or report is posted, a human author must confirm each item below:

- The manuscript names one exact artifact version, evidence cutoff, source revision, and execution environment.
- Every numerical result points to an output file, command, or versioned evidence record.
- Proposed or unmerged work is not described as a historical result.
- `0.3.1` is not called released, published, tagged, attested, or archived unless the release ledger contains observed evidence.
- Synthetic declaration-consistency fixtures are described as supplied static inputs and not as live framework discovery.
- Internal coverage, mutation, provenance, and traceability results are not described as security efficacy or independent assurance.
- The author list, contribution statement, disclosure statement, citations, ethics language, and artifact-archive choice are completed by the human authors.
- Any external evaluation states participant eligibility, consent, data minimization, task protocol, analysis method, and limitations before reporting outcomes.

## Evidence refresh matrix

| Candidate claim | Evidence required for a current report | Current state |
|---|---|---|
| The current artifact is reproducible | Exact current source revision, commands, environment, fixture hashes, outputs, and clean-install evidence | Repository-controlled preparation exists; final current-report bundle is not yet recorded. |
| Static declaration consistency can be reviewed | Versioned fixture suite, raw differences, declared mappings, unresolved labels, tests, and bounded examples | Prepared locally; not independently reproduced. |
| Reviewers can use the workflow | Independent participants execute the frozen packet and return structured observations | Not yet collected. |
| The tool improves review quality or speed | Predefined baseline, outcome metrics, controlled comparison, and analysis plan | Not yet collected. |
| A public package is reproducible | Exact release tag, package URLs, hashes, provenance verification, clean-install output, and release record | Verified for `0.3.0`; candidate `0.3.1` remains unpublished. |
| The artifact has a durable scholarly record | Owner-approved archive submission and confirmed persistent identifier | Not created. |

## Owner gates

The following actions are intentionally outside this record and require separate authorization at the time they are performed:

1. Choosing historical freeze versus a full paper refresh for public submission.
2. Tagging or publishing `0.3.1` to TestPyPI or PyPI.
3. Creating a GitHub Release or public announcement.
4. Recruiting reviewers or collecting participant feedback.
5. Submitting an archive or DOI record.
6. Making a current-paper, efficacy, adoption, certification, or security claim.

## References

[1]: ../archive/RELEASE_CANDIDATE_0.3.1.md "TrustWeave 0.3.1 release-candidate record"
[2]: ../../trustweave_research_paper/final/TRUSTWEAVE_RESEARCH_PAPER_POLISHED.md "TrustWeave research-paper draft"
[3]: ../../trustweave_research_paper/final/CLAIM_EVIDENCE_LIMITATION_MATRIX.md "TrustWeave claim-evidence-limitation matrix"
[4]: ../site/CURRENT_EVIDENCE.md "TrustWeave current-evidence ledger"
