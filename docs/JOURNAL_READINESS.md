# Journal readiness: what exists, what is missing, and what each gap costs

This is a self-assessment of the research in this repository as a *journal submission*, not
as engineering. It is written to be used against, so it names what is absent rather than
restating what is present, and it separates work the authors can do from judgements only a
reviewer makes.

## Status

Of the seven gaps below, **G1, G2, G3, G4, G5 and G7 are closed**, and **G6 is half
closed** -- the corpus is 8.8x larger than when the gap was written, but it is still vendor
test and conformance corpora rather than deployed policy, and that half is not closeable
from this repository. Each closure is marked at its heading with what closed it, and the
gap's original statement is left standing rather than rewritten, so the record shows what
was missing and not only what is present. The ceiling in [What the gaps are worth](#what-the-gaps-are-worth)
has not moved, because nothing closed here changes what sets it.

## What exists today

| Artifact | Size |
|---|---|
| The manuscript (LaTeX, **kept outside this repository**) | ~6,450 words, 8 numbered results, 15 references |
[`DECISION_CLASS_COVERAGE.md`](DECISION_CLASS_COVERAGE.md) -- the theory | ~4,600 words, 7 numbered results |
[`SUITE_COVERAGE_STUDY.md`](SUITE_COVERAGE_STUDY.md) -- the empirical study | ~4,600 words, 4 ecosystems |
| Evidence artifacts | 9 committed JSON records, each regenerable |
| Executable checks | every quoted figure pinned by a test |

The manuscript exists as LaTeX source and is **deliberately not committed to this
repository.** Journals and their similarity checks read a publicly posted full text as prior
dissemination, and a public repository is publicly posted; the safe default before submission
is to keep the paper out of it. It lives beside the checkout and is built on Overleaf.

Nothing is lost by that. `scripts/check_manuscript.py` still checks it -- structure, and
every figure it states pinned to the JSON an instrument wrote -- and takes the manuscript's
location from `TRUSTWEAVE_PAPER` or `--paper`:

```
TRUSTWEAVE_PAPER=/path/to/main.tex python scripts/check_manuscript.py
```

With no manuscript to find, that check and its tests report so and pass, because a checkout
without the paper is not a checkout with a wrong paper. The two documents above remain the
long-form development and stay here; the paper is what a reviewer reads, and it stays out.

## The gaps, worst first

### G1. There is no paper -- CLOSED

**Closed by** the manuscript and its bibliography: abstract, introduction with a contributions list,
formal development, evaluation, both negative results, threats to validity, related work
positioned against category-partition testing and the equivalent-mutant literature, and a
bibliography of 13 entries. The bibliography deliberately omits fields that were not
verified against a publisher record, and says so in its own header --- it must be completed
before submission.

A journal cannot assess what is not in submittable form. Section 8 of the theory document is
three objections answered in prose; that is not a survey of related work. The two documents
address a reader who has the repository open, not one who has the paper only.

**Closes it:** a manuscript. Abstract, introduction stating the contribution in one
paragraph, formal development, evaluation, threats, related work with a bibliography,
conclusion. **Who:** the authors. **This is a necessary condition -- no amount of further
technical work substitutes for it.**

### G2. The language has no formal semantics -- CLOSED

**Closed by** section 2 of the manuscript: the subject tuple with its seven components and
their domains, the guard grammar as a closed list of five forms, and the evaluation relation
as a function into a finite decision domain. Section 4 then shows the evaluation rule is the
part the results do not use, so the semantics is fixed without the theory depending on it.

`S`, `[[P]]` and `~P` are used throughout and never defined. The subject space is described
by a prose table. A reviewer cannot check Theorem 1 because the object it quantifies over is
not on the page.

**Closes it:** a syntax grammar, a definition of the subject tuple, and an evaluation
relation, before the theorems that speak about them. **Who:** the authors.

### G3. The proofs are sketches -- CLOSED

**Closed by** sections 3 and 4 of the manuscript: the finite-quotient theorem is now
factored through two lemmas, one per kind of component, each proved separately, and the
false step the earlier proof contained is stated as a remark with both of its
counterexamples rather than quietly repaired. The step that carried the error is
machine-checked (G7).

The four proofs run 138, 79, 62 and 25 words, with no lemma decomposition. That density is
not self-checking, and it did not check: one step claimed every capability subset is
occupied by some subject, which is false when patterns nest, and it survived until someone
tested it. The correction is recorded in the theory document.

**Closes it:** proofs at lemma granularity, and mechanisation of the steps that carry the
weight. **Who:** the authors.

### G4. The contribution is conceded but never assembled -- CLOSED

**Closed by** the manuscript's thesis paragraph and title, which state the assembled claim
--- that exact adequacy follows from a condition on guards and from nothing else, that the
evaluation rule is irrelevant to it, that most published policy satisfies it, and that the
cheap proxy for it does not measure it --- before any theorem is stated, and organise the
paper behind it.

Section 8 is right that the criterion is all-combinations coverage over a category-partition
in the sense of Ostrand and Balcer, and right to say so. What it never does is state, in one
sentence, what *is* new. Four things are, and they are stronger together than apart:

1. Exactness is a property of a policy's **guards**, not of a particular language. Theorem
   1b holds for any evaluation rule, checked under first-match, Cedar's forbid-overrides,
   Kyverno's any-rule-fails, and a four-valued XACML algorithm.
2. Fragment membership is **decidable and measured**: 15 of 21 XACML policies, 41 of 49
   Kyverno, 22 of 22 Cedar, with nothing left undetermined, and what puts a policy outside
   is one construct per ecosystem rather than general expressiveness.
3. The cheap proxy for the criterion is **near information-free** on real corpora -- 0.000
   bits on one of them -- and the informative threshold is interior, not `|D|`.
4. The study's one predictive result is **confined to policies outside the theory's scope**;
   inside it the effect is not distinguishable from zero.

Read as "an old criterion, made exact for our own DSL", this is incremental. Read as "exact
mutation adequacy for access-control policy is a property of guards, it is decidable, most
published policy has it, and the coverage proxy people would reach for does not measure it",
it is a dichotomy with a measurement and a negative result attached.

**Closes it:** stating that thesis first and organising the paper behind it. **Who:** the
authors.

### G5. Exactness is claimed against no baseline -- CLOSED

**Closed by** [`../scripts/estimator_comparison.py`](../scripts/estimator_comparison.py) and
section 6 of the manuscript: 42.1% of the mutant set is provably equivalent, so a suite whose
adequacy is complete by construction is reported at 57.9%.

The paper's practical claim is that a score is exact rather than approximate. It never
quantifies what the approximation costs. There is no comparison against sampling-based
estimation, and none against the equivalent-mutant heuristics the literature actually uses.

**Closes it:** an experiment measuring estimator error against the exact score on the
fragment, where the exact answer is available. **Who:** the authors. Cheap: the machinery
exists.

### G6. The corpora are small, and from vendor test suites -- HALF CLOSED

The gap named two things, and only one of them was about size.

**The size half is closed.** The membership measurement read 21 XACML policies, 49 Kyverno
and 22 Cedar -- 92 in total -- because it had been scoped to the policies a *suite* study
could also score, and scoring needs a suite. Membership needs none: it is decided from
policy text. Measured over the whole of each corpus it is **805 policies, 753 inside,
nothing undetermined**, which is 8.8x the evidence for the paper's external-validity claim
at no cost in rigour. Getting there took fixing the same mistake in two instruments -- an
allowlist of function *names* where the criterion is about *kinds* of guard -- and every
verdict in the original 92 is unchanged, which is the check that the widening added
decisions rather than moving them.

**The provenance half is not, and is the gap that caps the paper.** These are still the
projects' own test and conformance directories, not deployed policy, and the wide corpus is
now dominated by XACML's conformance suite -- written to exercise the specification's
function library, so it over-represents unusual functions and says little about what
production policy looks like. Reading its 96.0% as the deployed share would be wrong and the
paper's threats section says so. Separately, the Kyverno predictive experiment still has
nine policies in its blind arm and its p-value still does not survive stratification;
widening membership does not touch that, because the mutation scores it joins to exist only
for the 49.

**Closes the rest:** deployed policy, which the authors do not have, or a collaboration that
supplies it. **Who:** not the authors alone.

### G7. Nothing is mechanised -- CLOSED

**Closed by** [`../scripts/verify_witness_space.py`](../scripts/verify_witness_space.py):
the capability matching rule is encoded in SMT and the solver is asked, for every candidate
signature, whether any capability set realises it. Solver and construction agree on 8 of 8
pattern sets. This is the step whose proof was wrong, which is why it is the step that is
checked.

An SMT solver is available and unused. The witness construction is exactly the kind of claim
a solver should certify, and it is the claim that was wrong.

**Closes it:** encoding the guard language and checking achievability of every signature
against the construction. **Who:** the authors.

## What the gaps are worth

Closing G1 through G5 and G7 is entirely the authors' work and is the difference between
documentation and a submission. G6 is not, and the criterion's non-novelty is permanent and
correctly conceded.

**A fully executed version of this paper is a good paper, not a landmark one.** The honest
ceiling is set by two things no further work here changes: the central criterion is not new,
and the corpora are three vendor test suites. A paper can be rigorous, mechanised, honest
about a negative result, and still be a solid contribution rather than a field-shifting one.
Claiming otherwise in a cover letter is the fastest way to lose a reviewer.

## What to do next

The list that stood here --- manuscript, semantics, mechanisation, estimator comparison,
related work --- is done. What remains is not research:

1. **Compile the paper** on a machine with TeX, or on Overleaf. It has never been built, so
   the first compile will produce the ordinary crop of layout complaints. The structure and
   every figure are checked without compiling, so those are the only errors expected.
2. **Complete `refs.bib`** from publisher records. Volume, issue, page and DOI fields were
   left out rather than filled from memory, and the file's header says so. Confirm the
   `cedar2024` entry's canonical form, and record the pinned commits and access dates for
   the Kyverno and Gatekeeper corpora.
3. **Read the paper aloud once.** One pass has been done and it was worth doing --- it
   found three errors that the figure guard could not, because none of them was a number:

   - **Theorem 1's bound charged for components the policy never reads**, reporting 240
     cells for the running example, which has 12. Restated per component as
     `min(|D|, n+1)`, which is tight here and makes the unguarded case fall out with no
     clause of its own.
   - **Corollary 4 claimed that covering the quotient kills every non-equivalent mutant
     for any operator set.** False: `Delta(P, M)` is a union of classes of `~P` intersect
     `~M`, so a mutant drawing a distinction `P` does not can differ inside a cell the
     suite witnessed elsewhere. Now stated over a common refinement, with the clean
     quotient-level statement recovered for semantic mutants where it is also necessary.
     The implementation was right about this all along and its docstring said so; the
     paper had drifted from the code.
   - **Theorem 6's reduction used a guard that is not a predicate** -- `f` halts on `s` is
     semi-decidable, so it did not instantiate the theorem's own hypothesis. Replaced with
     a halting reduction whose guards are total.

   Two more passes by other authors are still worth having. The first pass found something
   substantive in each of the three theorem sections, which is not a rate that suggests the
   fourth pass will find nothing.
4. **Choose a venue against the ceiling below, not above it.** Software-testing or
   policy-analysis venues where an exactness result inside a characterised fragment is the
   contribution, and where a reported negative result is read as a virtue.

Corpus growth (G6) is worth pursuing in parallel and should not block submission, because
the paper's claims are already stated at the scope the corpora support, and its threats
section says so.
