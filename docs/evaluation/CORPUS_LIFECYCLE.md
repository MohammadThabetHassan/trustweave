# Synthetic Corpus Lifecycle

## Purpose

This policy governs changes to the TrustWeave synthetic evaluation corpus at `examples/evaluation-corpus/corpus.json`. Its purpose is to keep the corpus **local, deterministic, reviewable, and explicit about its limits**. It applies to the manifest, fixtures, runner, expected artifacts, regression tests, and documentation that describe the corpus.

> A passing corpus run demonstrates only that the checked-in implementation matched the checked-in expectations for supplied synthetic inputs. It does not demonstrate runtime enforcement, source authenticity, attack prevention, general security efficacy, adoption, or independent review.

## Current contract

| Contract element | Current value | Change rule |
|---|---|---|
| Corpus schema | `trustweave.dev/evaluation-corpus/v1alpha1` | A breaking field or semantic change requires a new schema version and compatibility documentation. |
| Corpus identifier | `trustweave-synthetic-evaluation-corpus` | This identifier is stable for the corpus lineage; a different corpus purpose requires a different identifier. |
| Corpus version | `v1alpha1` | Increment when the reviewed corpus expectations or included cases change. |
| Case identity | Ordered `TW-EVAL-001` through `TW-EVAL-NNN` identifiers | Existing case IDs are immutable. New cases append at the next contiguous identifier; deleted cases require an explicit migration record. |
| Execution boundary | Checked-in local paths and the established TrustWeave CLI only | No network, model, credential, agent, tool, server, target, or external-data behavior may be introduced. |

## What constitutes a corpus change

| Change type | Required accompanying work | Claim boundary |
|---|---|---|
| New synthetic case | Rationale, non-claim, expected exit, artifact/assertion contract where relevant, and a public regression test. | The case is a designed synthetic control, not a prevalence or coverage estimate. |
| Changed expectation | Written behavioral rationale, affected-output review, regression update, and corpus-version update. | A changed expected result does not retroactively alter prior evidence. |
| Fixture correction | Deterministic reproduction of the defect, test showing the corrected behavior, and a description of whether the corpus expectation changes. | Fixture correctness does not authenticate a real-world source. |
| Runner contract change | Tests for valid and invalid contracts, documentation update, and an explicit compatibility decision. | Runner validation does not establish that a supplied input is truthful or complete. |
| Breaking schema or semantics change | New schema version, migration guidance, retained historical reader behavior where applicable, and a fresh baseline record. | New schema semantics do not redefine historical reports. |

## Required procedure

A maintainer proposing a corpus update must first classify the change using the preceding table. The pull request must identify the current and proposed corpus version, the affected case IDs, the behavioral reason, and whether any public documentation needs updating.

Before review, run the local preflight command. It validates the corpus manifest and checked-in path boundaries without executing any case:

```bash
python scripts/run_evaluation_corpus.py --check
```

Then run the full synthetic corpus in a fresh local output directory:

```bash
python scripts/run_evaluation_corpus.py --verify
```

The change must also satisfy the repository’s complete local quality suite. New cases require at least one regression assertion that fails when the intended corpus invariant is violated. Changed results require a reviewer-visible explanation; muting, deleting, or relabeling an unexpected result solely to preserve a passing summary is prohibited.

## Review and release rules

Corpus modifications require a human maintainer review for scope, safety boundary, expected behavior, and documentation accuracy. A reviewer must confirm that every input path is checked in, every case carries a specific non-claim, and no case requests sensitive or external data. The project may publish the corpus version, case count, and deterministic pass/fail result only after the corresponding change is merged and verified on the relevant commit.

A corpus change must not be described as an independent evaluation result, benchmark result, pilot outcome, security proof, or adoption metric. Those labels require separately collected, consented, and disclosed evidence under the evaluation charter and status ledger.

## Rollback and history

If a newly merged corpus change is found to contain an incorrect fixture or expectation, preserve the original commit and correct it in a new commit. Do not rewrite shared history. The corrective pull request must identify the affected corpus version, summarize the discrepancy, retain any affected prior output as historical evidence where safe, and explain the new expected behavior.

Historical corpus schemas and public evidence records remain versioned rather than silently redefined. A future durable archive or research report must identify the exact corpus version and repository commit used to produce its results.
