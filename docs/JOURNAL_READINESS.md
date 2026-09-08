# Journal readiness: what exists, what is missing, and what each gap costs

This is a self-assessment of the research in this repository as a *journal submission*, not
as engineering. It is written to be used against, so it names what is absent rather than
restating what is present, and it separates work the authors can do from judgements only a
reviewer makes.

## Status

Of the seven gaps below, **G1, G2, G3, G4, G5 and G7 are closed**, and **G6 is mostly
closed** -- the corpus is 28.7x larger and has five ecosystems rather than three, and one of
them is deployed policy, but it is still vendor
test and conformance corpora rather than deployed policy, and that half is not closeable
from this repository. Each closure is marked at its heading with what closed it, and the
gap's original statement is left standing rather than rewritten, so the record shows what
was missing and not only what is present. The ceiling in [What the gaps are worth](#what-the-gaps-are-worth)
has not moved, because nothing closed here changes what sets it.

## What exists today

| Artifact | Size |
|---|---|
| The manuscript (LaTeX, **kept outside this repository**) | ~8,800 words, 16 pages, 13 numbered results, 17 references, compiles clean |
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
bibliography of 15 entries, every one checked against the publisher's record via Crossref:
authors, title, venue, year, volume, issue, pages and DOI, with eleven carrying a DOI.

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
policy text. Measured over the whole of each corpus, and with Rego added, it is **991
policies, 869 inside, nothing undetermined** across four ecosystems -- 10.8x the evidence
for the paper's external-validity claim, at no cost in rigour. Every verdict in the original
92 is unchanged, which is the check that the widening added decisions rather than moving
them.

Two mistakes had to be fixed to get there, and both were the same kind. In XACML and Kyverno
the instruments held allowlists of function *names* where the criterion is about *kinds* of
guard. And Rego had been left out altogether on the strength of an argument about the
language rather than a measurement of its policies -- the argument was right that Rego *can*
leave the fragment and wrong that its published policies do, and it took an AST-reading
adapter with import propagation to find that out.

**The provenance half is now half-answered too, and the premise it rested on was wrong.**
This note said the gap needed "deployed policy, which the authors do not have". AWS
publishes its managed IAM policies, they are attached in accounts worldwide, and IAM is the
most widely used access-control policy language there is -- so the policy was there, and the
claim that it was not had never been checked. **1,651 of 1,651 AWS managed policies are
inside the fragment**, pinned at a commit, and the corpus is now 2,642 policies across five
ecosystems with 2,520 inside.

Two caveats ship with that, and the second is the one to keep. IAM is 62% of the pooled
corpus and drags the total to 95.4%; excluding it the figure is 87.7%. And the IAM adapter
has no path to a verdict of `outside`, so 100% is not the result of looking for exclusions
and finding none -- it is principled, since IAM has no construct for reading state the
evaluator was not handed, but it is weaker evidence than Kyverno's 87.2%, where the
instrument had an outside branch and used it thirty times.

**What still caps the paper.** Four of the five corpora are still the projects' own test and
conformance directories, and the non-IAM corpus is over half XACML's conformance suite -- written to exercise the specification's function
library, so it over-represents unusual functions and says little about what production
policy looks like. Reading its 96.0% as the deployed share would be wrong, the pooled 87.7%
inherits that skew, and the paper's threats section says both. Separately, the Kyverno predictive experiment still has
nine policies in its blind arm and its p-value still does not survive stratification;
widening membership does not touch that, because the mutation scores it joins to exist only
for the 49.

**Closes the rest:** policy written by the organisations that run it, rather than published
by the vendors that ship the engine. AWS's managed library is deployed but it is still one
vendor's library, not what its customers write. That needs a collaboration, or a corpus
mined from infrastructure repositories that *use* these engines -- the second is possible
from here and has not been attempted. **Who:** the authors could attempt the mining; the
collaboration is not theirs alone to arrange.

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

1. ~~**Compile the paper.**~~ **Done, and it was worth doing.** The blocker was recorded as
   "no TeX on this machine and no privileges to install one", and that was true of the
   package manager and wrong about the problem: Tectonic is a single static binary that
   needs no root and fetches packages on first run. The build is clean --- **13 pages, no
   errors, no undefined references or citations, no overfull boxes**, one underfull box in a
   bibliography entry with a long URL. Three overfull boxes and a numbering question were
   found and fixed in the process, none of which any check in this repository could have
   seen, because a document that has never been built has no layout to be wrong.

   The lesson is worth keeping beside the finding: "the environment cannot do this" deserves
   one more attempt than it usually gets.
2. **Record the pinned commits and access dates for the three software entries.** The rest
   of the bibliography is done: all fifteen entries are verified against the publisher's
   record, and the two citations that had been flagged as unconfirmed both exist and were
   cited correctly -- Martin and Xie, WWW 2007, pp. 667--676, and the Cedar paper, PACMPL
   8(OOPSLA1), pp. 670--697. Worth stating plainly, because the alternative to checking a
   half-remembered citation is a fabricated reference in a submitted paper.
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

   A second pass has since been done and found two more, both of the same kind as the
   first three -- a claim contradicting something the code already knew:

   - **The boundary list contradicted the Cedar measurement.** Both documents named
     "transitive membership over an entity store of unbounded depth" as a guard *outside*
     the fragment. Cedar's `in` is exactly that guard and Cedar measures 22 of 22 inside;
     `fragment_membership_cedar.py` had the correct reasoning in its own header throughout.
   - **The worked example's explanation of the equivalence rate was wrong about two
     mutants**, and its arithmetic still added up, which is how it survived. Two widenings
     reach the one cell that decides `require_approval`; they are equivalent because an
     earlier rule claims it, not because the default does. The paper had also read
     Theorem 1b as making the reorderings equivalent under *any* combining function, which
     it does not: a swap permutes which guard feeds which argument.

   Both passes found things no figure guard can see, because none of the five findings was
   a number. Two of the five were the prose disagreeing with an instrument that was already
   right, which is the failure mode to watch for in a repository that keeps its documents
   next to its measurements. A third pass by another author is still worth having; a rate
   of five findings over two passes is not a rate that suggests the next one is empty.
4. **Mine a corpus from repositories that *use* these engines,** rather than from the
   repositories that ship them. This is the remaining half of G6 and it is possible from
   here: infrastructure-as-code repositories carry Kyverno `ClusterPolicy` and Gatekeeper
   `Constraint` manifests written by the organisations that run them. Not attempted.
5. ~~**Settle whether finite refinement is necessary as well as sufficient.**~~ **Done, and
   it is necessary.** For effective finite-outcome guard families over an enumerable subject
   space and a cell-expressive language, policy equivalence is decidable **if and only if**
   the condition holds. Theorem 6 becomes a corollary. Two things fell out that were worth
   more than the theorem:

   - **The definition's finiteness clause does no work.** A guard reporting finitely many
     outcomes gives an outcome map into a finite set whatever the guard is -- the halting
     guard included -- so the clause is free, and all the content is in witnesses. A reading
     that treats finiteness as the substance has it backwards.
   - **The solver was already checking the right predicate.** `verify_witness_space.py`
     certifies which candidate signatures are *achievable*, and achievability is occupancy,
     which is the predicate the tightness theorem identifies as exactly the one that matters.
     That was not why it was written.

   Also separated: deciding *equivalence* needs occupancy and no witness, while the results
   about *suites* need a witness one can put in a test case. The definition had bundled two
   requirements serving different halves of the development.
6. **Choose a venue against the ceiling below, not above it.** Software-testing or
   policy-analysis venues where an exactness result inside a characterised fragment is the
   contribution, and where a reported negative result is read as a virtue.

Corpus growth (G6) is worth pursuing in parallel and should not block submission, because
the paper's claims are already stated at the scope the corpora support, and its threats
section says so.
