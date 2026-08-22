# Synthetic evaluation framework

TrustWeave includes a versioned, local-only synthetic corpus for checking whether the tool produces the documented review categories from supplied declarations and minimized metadata. The corpus is designed for reproducibility and evidence clarity; it is not a live-agent test, penetration test, or runtime security benchmark.

## Run the corpus

From a local checkout with development dependencies installed, validate the checked-in corpus contract before executing any case:

```bash
python scripts/run_evaluation_corpus.py --check
```

Then run the corpus:

```bash
python scripts/run_evaluation_corpus.py --verify
```

The preflight validates the stable corpus identity, ordered case IDs, local path boundaries, and assertion shapes without running a case. The verification command runs twelve checked-in synthetic cases in a temporary local directory and returns non-zero only when a corpus expectation does not match. Review-required cases are expected controls when their declared exit state and finding category match.

## What the corpus covers

| Area | Evidence produced | Important limit |
|---|---|---|
| Manifest validation | Fail-closed errors for missing declared trust or classification data. | It does not authenticate supplied declarations. |
| Policy review | Clear and review-required local policy artifacts. | It does not enforce policy at runtime. |
| Bundle diff | Review signals for declared capability and approval-control changes. | It does not discover undeclared deployed changes. |
| Trace review | Local comparison of minimized metadata with supplied flows and policy. | It does not inspect message content, tool arguments, or trace completeness. |
| MCP metadata profile review | Local mapping and action-class review from supplied metadata. | It does not connect to, discover, or authenticate an MCP server. |

## Evidence status

The corpus and future reviewer protocol are prepared foundations. Independent reviewer responses, pilots, comparative benchmark outcomes, adoption evidence, and a durable research archive are **not yet collected**. The project will report those only after they exist, are consented where required, and are reviewed against the stated evidence rules.

For the complete operational materials, see the repository’s [evaluation charter](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/evaluation/EVALUATION_CHARTER.md), [reviewer quickstart](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/evaluation/REVIEWER_QUICKSTART.md), prepared [offline reviewer packet](https://github.com/MohammadThabetHassan/trustweave/tree/main/examples/evaluation-corpus/reviewer-packet), [corpus lifecycle](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/evaluation/CORPUS_LIFECYCLE.md), [archive-readiness checklist](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/evaluation/ARTIFACT_ARCHIVE_READINESS.md), [local artifact-manifest tool](https://github.com/MohammadThabetHassan/trustweave/blob/main/scripts/build_evaluation_artifact.py), [data-minimization policy](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/evaluation/DATA_MINIMIZATION_POLICY.md), and [status ledger](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/evaluation/STATUS.md).

> Passing this corpus demonstrates only conformance on supplied synthetic inputs. It does not demonstrate runtime enforcement, input authenticity, attack prevention, general security efficacy, user adoption, or productivity outcomes.
