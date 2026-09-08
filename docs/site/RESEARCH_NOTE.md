# Where the research write-ups are

This repository holds the instruments and the evidence. It does not hold the write-ups.

`docs/*.json` in the repository carries the measured results — fragment membership across six policy
languages, the estimator comparison, the threshold and trend analyses, the solver
certificate — and `scripts/` carries the code that produced each one. Every figure is
reproducible from what is here: point an adapter at the corpus commit its artifact records
and you get the same numbers.

The prose that explains those numbers is kept outside the repository until the work is
submitted. A journal, and the similarity check it runs, treats a publicly posted full text
as prior dissemination, and a public repository is publicly posted. That applies to the
manuscript and equally to the long-form development it was written from, so the theory
write-up, the suite-coverage study, the readiness assessment and the prospectus all live
beside it rather than here.

Nothing is hidden by this and nothing is lost. The artifacts are the claims; the write-ups
argue about them. A reader who wants the argument before publication should ask the authors
for it.

## Running the checks that need them

Two guards read the theory write-up, because a hand-copied table in a proof document is a
claim like any other and should not go unchecked. They follow it through an environment
variable and skip when it is absent:

```
TRUSTWEAVE_RESEARCH_DIR=/path/to/write-ups pytest tests/test_decision_class_theory.py
TRUSTWEAVE_PAPER=/path/to/main.tex python scripts/check_manuscript.py
```

Without those set, both report that they have nothing to check and pass. A checkout without
the write-ups is not a checkout with wrong ones.

## What stays here

- `scripts/fragment_membership*.py`, `scripts/policy_mutation.py` and the rest of the
  measurement code.
- `docs/*.json` — every artifact, each recording the corpus commit it read.
- The engineering documents that describe the tool rather than the research.

Cite the artifacts if you need a figure before the paper appears. They are the primary
record, and the write-ups quote them rather than the other way round.
