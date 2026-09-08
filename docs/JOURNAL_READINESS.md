# Journal readiness: what exists, what is missing, and what each gap costs

This is a self-assessment of the research in this repository as a *journal submission*, not
as engineering. It is written to be used against, so it names what is absent rather than
restating what is present, and it separates work the authors can do from judgements only a
reviewer makes.

## What exists today

| Artifact | Size |
|---|---|
[`DECISION_CLASS_COVERAGE.md`](DECISION_CLASS_COVERAGE.md) -- the theory | ~4,600 words, 7 numbered results |
[`SUITE_COVERAGE_STUDY.md`](SUITE_COVERAGE_STUDY.md) -- the empirical study | ~4,600 words, 4 ecosystems |
| Evidence artifacts | 9 committed JSON records, each regenerable |
| Executable checks | every quoted figure pinned by a test |

There is **no manuscript**. No abstract, no related-work section, no bibliography, no
figures, no threats-to-validity section as such. Everything above is repository
documentation that happens to contain research.

## The gaps, worst first

### G1. There is no paper

A journal cannot assess what is not in submittable form. Section 8 of the theory document is
three objections answered in prose; that is not a survey of related work. The two documents
address a reader who has the repository open, not one who has the paper only.

**Closes it:** a manuscript. Abstract, introduction stating the contribution in one
paragraph, formal development, evaluation, threats, related work with a bibliography,
conclusion. **Who:** the authors. **This is a necessary condition -- no amount of further
technical work substitutes for it.**

### G2. The language has no formal semantics

`S`, `[[P]]` and `~P` are used throughout and never defined. The subject space is described
by a prose table. A reviewer cannot check Theorem 1 because the object it quantifies over is
not on the page.

**Closes it:** a syntax grammar, a definition of the subject tuple, and an evaluation
relation, before the theorems that speak about them. **Who:** the authors.

### G3. The proofs are sketches

The four proofs run 138, 79, 62 and 25 words, with no lemma decomposition. That density is
not self-checking, and it did not check: one step claimed every capability subset is
occupied by some subject, which is false when patterns nest, and it survived until someone
tested it. The correction is recorded in the theory document.

**Closes it:** proofs at lemma granularity, and mechanisation of the steps that carry the
weight. **Who:** the authors.

### G4. The contribution is conceded but never assembled

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

### G5. Exactness is claimed against no baseline

The paper's practical claim is that a score is exact rather than approximate. It never
quantifies what the approximation costs. There is no comparison against sampling-based
estimation, and none against the equivalent-mutant heuristics the literature actually uses.

**Closes it:** an experiment measuring estimator error against the exact score on the
fragment, where the exact answer is available. **Who:** the authors. Cheap: the machinery
exists.

### G6. The corpora are small, and from vendor test suites

21 XACML policies, 49 Kyverno, 22 Cedar, all from the projects' own test directories rather
than from deployed policy. The Kyverno predictive experiment has nine policies in its blind
arm and its p-value does not survive stratification.

**Closes it:** deployed policy, which the authors do not have, or a collaboration that
supplies it. **Who:** not the authors alone. This is the gap that caps the paper.

### G7. Nothing is mechanised

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

## What to do first

1. **The manuscript**, with the thesis of G4 stated in the abstract.
2. **Formal semantics**, so the proofs have an object.
3. **Mechanised witness construction**, because that is where the error was.
4. **The estimator comparison**, because the exactness claim is the practical one.
5. **Related work**, positioning against category-partition testing, mutation adequacy, and
   the equivalent-mutant literature.

Corpus growth is worth pursuing in parallel and should not block submission, because the
paper's claims are already stated at the scope the corpora support.
