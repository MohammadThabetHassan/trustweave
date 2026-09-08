# The manuscript

`main.tex` is the paper; `refs.bib` is its bibliography. Both are source, and neither has
been compiled in this repository, because no TeX distribution is installed on the machine
the work was done on and installing one needs privileges the authors do not have there.
That is a statement about the environment, not about the source: the structure is checked on
every run of the reality check, and so is every number.

## Building it

The paper uses only `amsmath`, `amssymb`, `amsthm`, `booktabs`, `hyperref`, `geometry` and
`microtype`, all of which ship with a standard distribution, so any of these works:

```
# Overleaf: upload main.tex and refs.bib, set the compiler to pdfLaTeX. Nothing else.

# Locally, with texlive-latex-recommended and texlive-bibtex-extra installed:
pdflatex main && bibtex main && pdflatex main && pdflatex main

# Or in one step:
latexmk -pdf main.tex
```

Three passes are needed because the cross-references and the bibliography each want one.

## What is checked without compiling

`scripts/check_manuscript.py` runs on every reality check and in CI. It does two things.

**Structure.** A citation with no bibliography entry, a bibliography entry never cited, an
unbalanced environment or brace, a `\ref` to a label that does not exist. These are exactly
the errors a compile would catch, so they have to be caught by reading instead.

**Figures.** Every quantitative claim in the paper is derived from the JSON an instrument
wrote under `docs/`, and the check fails if the two disagree. Each claim is pinned by an
anchored pattern rather than a substring search, because a substring search only asks
whether the right number appears *somewhere*, and so passes a paper that states a figure
correctly in one section and wrongly in another --- which is the drift revision actually
produces. Every occurrence of a claim's phrasing must carry the artifact's value, and a
claim whose phrasing has been edited away fails as "no longer stated" rather than passing
quietly.

Run it directly with:

```
python scripts/check_manuscript.py
```

Consequences worth knowing before editing:

- **Rewording a sentence that carries a number will fail the check.** That is deliberate.
  Re-anchor the pattern in `numeric_claims()` to the new phrasing; do not delete the claim.
- **Changing a number in the paper alone will fail.** Numbers come from the artifacts. To
  change one, re-run the instrument that produced it.
- **Adding a figure to the paper does not add a pin.** Pin it, or the next revision can
  break it silently.

## Before submitting

- `refs.bib` deliberately omits volume, issue, page and DOI fields that were not verified
  against a publisher record, rather than filling them from memory. Its header says so.
  Complete them from the publisher or DBLP. **Do not submit the file as it stands.**
- The `cedar2024` entry needs its canonical citation confirmed; the note in the file
  explains the fallback if it cannot be.
- The `kyverno` and `gatekeeper` entries want the pinned commit hashes and access dates
  that `docs/SUITE_COVERAGE_STUDY.md` records.
- `docs/JOURNAL_READINESS.md` lists what remains open and what caps the work. Read it before
  deciding where to submit; in particular G6, the corpus limitation, is not closeable from
  this repository and the paper says so in its threats section rather than hiding it.
