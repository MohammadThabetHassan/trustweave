# Where the research write-ups are

This repository holds the research instruments and their results. The papers written from them
will appear here once they are published: a journal treats a full text that is already posted in
a public repository as prior publication.

## What is here

- `docs/*.json`: every measurement artifact, including fragment membership across six policy
  languages, the estimator comparison, the threshold and trend analyses and the solver
  certificate. Each artifact records the corpus commit it read.
- `scripts/`: the code that produced each artifact, such as `scripts/fragment_membership*.py` and
  `scripts/policy_mutation.py`.
- `scripts/oracle_rego.py` and `scripts/interpreter_oracle.py`, which check two instruments
  against an independent reference: the Rego adapter against OPA's own dependency analysis, and
  the decision map against the shipped engine. Each needs its subject present (for the first,
  `opa` on the path and the pinned corpora) and writes an artifact under `docs/` that lists what
  it found.
- The engineering documents that describe the tool itself.

Every figure can be reproduced from these files: run an adapter against the corpus commit its
artifact records and the same numbers come back.
[Reproducing the study](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/REPRODUCING_THE_STUDY.md)
maps each artifact to the command that writes it.

## Checks that read the write-ups

Two checks compare the write-ups with the artifacts, so that a table copied into a proof or a
paper cannot drift from the data. They find the documents through environment variables and skip
when those are unset:

```
TRUSTWEAVE_RESEARCH_DIR=/path/to/write-ups pytest tests/test_decision_class_theory.py
TRUSTWEAVE_PAPER=/path/to/main.tex python scripts/check_manuscript.py
```

## Citing results before publication

Cite the artifacts: they are the primary record, and the write-ups quote them. To read a write-up
before it is published, contact the authors.
