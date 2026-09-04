# Decision-class coverage: the fragment, and what is exact within it

`scripts/policy_mutation.py` reports a mutation score without sampling and without a manual
equivalent-mutant audit. That is not a better heuristic; it is a consequence of the policy
language being restricted enough that the relevant questions are decidable. This document
states the restriction, proves what follows from it, and marks where it stops holding.

Every claim here is checked by `tests/test_decision_class_theory.py`, which verifies the
theorems by exhaustive enumeration against the shipped policy and the real mutant set rather
than restating them.

## 1. The language and its subject space

A **policy** is a finite ordered sequence of rules with a mandatory default decision
`d_0 in D`, where `D = {allow, deny, require_approval}`. Evaluation is first-match: the
decision of the first rule whose every predicate holds, or `d_0`.

A **subject** is the tuple of declared labels a rule may test:

| Component | Domain | Predicate the language offers |
|---|---|---|
| trust | `T`, 3 values | membership in a named set |
| action class | `A`, 4 values | membership in a named set |
| data classification | any string | membership in a named set; bounds over a declared taxonomy |
| source identifier | any string | membership in a named set |
| tool identifier | any string | membership in a named set |
| purpose tags | any *set* of strings | non-empty intersection with a named set |
| capabilities | any *set* of strings | some capability matches some named pattern, where a pattern is exact or a final `.*` namespace wildcard |

**The subject space is infinite.** Identifiers, purposes and capabilities are arbitrary
strings, and two of the components are sets rather than scalars. There is no 12-cell domain
to enumerate, and an earlier version of this document wrongly described one: it stated the
fragment as *policies that constrain only trust and action*, which is a property of the one
policy shipped rather than of the language.

What is true, and what everything below rests on, is that the space is finite *relative to
a policy*.

## 2. The policy-relative quotient

For a policy `P`, write `~P` for the relation on subjects that holds when two subjects give
the same answer to every predicate any rule of `P` states. Since first-match evaluation
consults nothing else, `[[P]]` is constant on each class of `~P`.

**Theorem 1 (finite quotient).** For every policy `P`, the quotient `S/~P` is finite and
computable from `P`'s text, with

```
|S/~P|  <=  |T| . |A| . (|X_P| + |taxonomy| + 1) . (|I_P| + 2) . (|J_P| + 2) . 2^|G_P| . 2^|K_P|
```

where `X_P`, `I_P`, `J_P`, `G_P`, `K_P` are the classifications, source identifiers, tool
identifiers, purpose tags and capability patterns the policy names.

*Proof.* Take each component in turn. Trust and action range over closed finite domains.
A membership predicate over a named set `N` distinguishes only which element of `N` a value
is, or that it is in none, so `|N| + 1` classes suffice; classification adds the taxonomy
because the bound predicates compare ranks within it. Purpose matching is non-empty
intersection with a named set, so only the *subset of named tags* a subject carries matters:
`2^|G_P|` classes. Capability matching is existential over (named pattern, subject
capability), so only the *subset of named patterns some capability matches* matters:
`2^|K_P|` classes, and each is witnessed, since a pattern `n.*` is matched by `n.w` for any
`w` and an exact pattern by itself. Subjects agreeing on every component agree on every
predicate, hence match the same rules, hence receive the same decision. []

`witness_space()` computes one representative per class and `cells()` enumerates the
product; `abstract_cell()` maps a concrete subject to its representative. For the shipped
policy, which names no classification, purpose or capability, the bound collapses to
`3 . 4 = 12` -- so the twelve cells are the whole space for *that* policy rather than a
projection of it.

Theorem 1 is the load-bearing claim and it is checked, not merely argued:
`tests/test_decision_class_theory.py` draws random subjects over open domains -- unnamed
identifiers, unnamed purposes, capabilities inside and outside a wildcard namespace -- and
asserts each decides exactly as its class witness does. Breaking the abstraction makes that
test fail.

**Theorem 2 (decidable equivalence).** For policies `P` and `Q`, semantic equivalence is
decidable: quotient by `~P n ~Q` -- computed from the values *either* policy names -- and
compare the decision each gives on every class. The cost is the size of that common
refinement, bounded as above with the named sets unioned.

*Proof.* `[[P]]` and `[[Q]]` are each constant on classes of the common refinement by
Theorem 1, so agreement on one representative per class is agreement everywhere. []

This is what removes the equivalent-mutant problem. Deciding whether a surviving mutant is
equivalent to the original is undecidable for programs in general, so tools approximate the
score or a human inspects survivors. Here it is a comparison of two finite tables. The
harness checks that a mutant names no value the reference does not, so the two quotients
coincide and one table shape serves both; a mutant that widened the space would be refused
rather than compared across incompatible partitions.

## 3. Cells, and what a cell is

Throughout the rest of this document a **cell** means a class of the quotient of Theorem 1,
and `S` means `S/~P`. Nothing below depends on which components a policy happens to use:
a policy naming only trust and action has twelve cells, one that also bounds classification,
names two purpose tags and two capability patterns has 960, and the statements are the same.

## 4. What a suite can detect

A **suite** `Sigma` is a finite set of cases `(s, d)` with `s in S` and `d in D`. Write
`W(Sigma) = {s : (s, d) in Sigma for some d}` for the **witnessed cells**. `Sigma` is
**consistent** with `P` when `d = [[P]](s)` for every case -- a suite that contradicts its own
policy fails before any mutant is considered, so consistency is assumed throughout.

`Sigma` **kills** a mutant `M` when some case fails against it: `[[M]](s) != d`.

Write `Delta(P, M) = {s in S : [[P]](s) != [[M]](s)}` for the cells where a mutant deviates.

**Theorem 3 (exact kill criterion).** For consistent `Sigma`,

```
Sigma kills M   <=>   Delta(P, M) intersect W(Sigma) != empty
```

*Proof.* (<=) Let `s` be in both sets. Since `s in W(Sigma)` there is a case `(s, d)` in
`Sigma`, and consistency gives `d = [[P]](s)`. Since `s in Delta(P, M)` we have
`[[M]](s) != [[P]](s) = d`, so that case fails and `Sigma` kills `M`.
(=>) Suppose `Sigma` kills `M` via a case `(s, d)`, so `[[M]](s) != d`. Consistency gives
`d = [[P]](s)`, hence `[[P]](s) != [[M]](s)`, so `s in Delta(P, M)`; and `s in W(Sigma)` by
definition. []

Detection depends only on *which cells the suite witnesses*, never on how many cases it
holds. A suite of a thousand cases concentrated on four cells detects exactly what a
four-case suite on those cells detects.

**Corollary 4 (cell coverage decides the score).** If `W(Sigma) = S` then `Sigma` kills every
non-equivalent mutant, for any mutation operator set whatsoever: a non-equivalent mutant has
`Delta(P, M)` non-empty by Theorem 2, and it meets `W(Sigma) = S`. The mutation score is
100% by construction rather than by measurement.

The converse needs care, and the care is the point. If `W(Sigma) != S`, pick `s` outside it
and `d != [[P]](s)`. The *semantic* mutant that agrees with `P` everywhere except at `s`,
where it returns `d`, is non-equivalent and survives `Sigma`. So over the family of all
single-cell perturbations, full cell coverage is necessary as well as sufficient for a 100%
score. Over the *syntactic* operator set an implementation actually generates -- deleting a
rule, flipping a decision, widening a guard -- the surviving mutant is guaranteed only if
that set happens to realise such a perturbation. A syntactic operator set can therefore
report 100% against an incomplete suite. That is a limitation of the operator set, and it is
why `scripts/policy_mutation.py` reports witnessed cells alongside the score instead of the
score alone.

**Corollary 5 (decision-class coverage is not sufficient, and is necessary only relative to
the policy's range).** Let a suite's **decision classes** be `{d : (s, d) in Sigma}`. Under
consistency these are exactly `{[[P]](s) : s in W(Sigma)}` -- the image of the witnessed
cells, not a free parameter of the suite.

*Not sufficient.* A suite may expect every decision in `D` while witnessing few cells. Take
one cell per decision: three cells of twelve, all three classes expected, and Theorem 3
leaves the other nine undefended.

*Necessary, but only where the policy reaches the decision.* If `Sigma` achieves full
detection then `W(Sigma) = S` by the converse in Corollary 4, so `Sigma` expects exactly the
image of `[[P]]`. A missing decision class therefore certifies an unwitnessed cell **when the
policy can return that decision**. If `[[P]]` never returns `d`, no suite expects `d` and
none needs to -- so an unexpected class is evidence of a gap only against a policy whose
range includes it. Reporting missing decision classes without that check would flag a
complete suite for a policy that simply never approves anything.

`benchmark/orthogonality-witness` is Corollary 5 made concrete: a suite at 100% structural
coverage, expecting decisions in every class, that cannot detect its policy's default
changing.

## 5. Why this is not just mutation testing with extra steps

Structural coverage asks whether a line ran. Mutation testing asks whether a change would be
noticed, and normally answers approximately, because equivalence is undecidable and the
mutant space is large. Within this fragment both obstacles disappear: Theorem 2 makes
equivalence a table comparison, and Theorem 3 reduces detection to a set intersection over
twelve cells. The adequacy question becomes arithmetic.

The practical consequence is Corollary 4. A team does not need to run mutation testing on
such a policy at all -- they need to witness every cell, which is checkable directly and
costs one pass over the suite. Mutation testing here is a way to *validate* that claim, not
the cheapest way to satisfy it.

## 6. The theorems on the shipped policy

`scripts/policy_mutation.py` against `policies/default-policy.json`, whose 12 cells and
three decisions are the fragment exactly. 38 mutants are generated and 16 are discarded as
equivalent by Theorem 2, leaving 22 live.

| Suite | Cases | Cells witnessed | Killed | Score | Decision classes missing |
|---|---|---|---|---|---|
| `default-scenarios` | 5 | 5/12 | 14/22 | 63.6% | none |
| `adversarial-scenarios` | 25 | 3/12 | 8/22 | 36.4% | `allow` |
| `coverage-matrix-scenarios` | 12 | 12/12 | 22/22 | 100.0% | none |

Three things in that table are the theorems rather than observations about these
particular files.

The adversarial suite holds five times the cases of the default suite and detects less: 25
cases over 3 cells kill 8 mutants, where 5 cases over 5 cells kill 14. Theorem 3 says
detection depends on witnessed cells and not on case count, and here the two run in
opposite directions. Case count is not weak evidence of adequacy; it is no evidence.

The coverage matrix witnesses all 12 cells and kills all 22 live mutants. That is Corollary
4, and it is not a measurement that happened to come out well -- with full cell coverage no
other result is possible, for any operator set. A team could have concluded this without
running mutation testing at all.

The default suite expects every decision class and still kills only 63.6%. That is
Corollary 5: decision-class completeness is necessary and not sufficient, and the gap
between the two is the nine cells it never witnesses.

## 7. Where this ends

**Theorem 6.** If rule guards may contain arbitrary computable predicates, policy
equivalence is undecidable.

*Proof sketch.* Semantic equivalence to a fixed policy is a non-trivial property of the
extensions of the guard programs, so Rice's theorem applies: no total procedure decides,
for arbitrary guard programs, whether two policies agree on every subject. []

So the results above are a property of *this* language, and specifically of the fact that
every predicate it offers -- set membership, rank bounds over a declared taxonomy, set
intersection, final-namespace wildcards -- induces finitely many classes computable from the
policy text. Add a predicate that does not, a regular expression over identifiers say, or a
numeric comparison against a value the policy does not name, and Theorem 1's bound stops
holding. That is the boundary to watch when the language grows, and it is a design
constraint on the language rather than a limitation of the tool.

Two practical limits remain. The quotient is a *product*, so it grows multiplicatively in
the number of purpose tags and capability patterns a policy names: twenty named purpose tags
alone put it past a million classes. `cells()` refuses above a fixed bound rather than
sampling, because an exact score over a sampled subspace would not be exact. And the
comparison in Theorem 2 requires the two policies to induce the same quotient; the harness
checks this and refuses rather than comparing tables of different shapes.

Rego, Cedar and Kyverno sit outside all of this: their subjects are arbitrary JSON or entity
graphs and their guards are general expressions, so no enumeration exhausts them. The
measurement in `docs/SUITE_COVERAGE_STUDY.md` is therefore an observation about those
suites, not a proof about them -- it reports which decisions a suite pins, which is well
defined everywhere, while the exactness results here require the finite quotient.

## 8. Relation to existing criteria

Three objections are the obvious ones, and the honest answers are not all favourable.

**"Decision coverage already means something else."** It does. In ISTQB usage and in
DO-178C, decision coverage is branch coverage: every branch outcome taken at least once. It
is a structural criterion over program text. What is defined here is a criterion over a
policy's *output* -- which decisions of the label domain a suite pins -- and the two are not
comparable. `benchmark/orthogonality-witness` exists precisely because a suite can satisfy
the structural one completely while failing the output one. The collision is unfortunate and
any write-up must define the term on first use rather than rely on it.

**"Witnessing every cell is just exhaustive testing over an input partition."** Correct, and
this is the answer that matters. `S = T x A` is a category-partition in the sense of Ostrand
and Balcer, and witnessing all of `S` is all-combinations coverage over two categories. As a
*criterion* there is nothing new in it, and claiming otherwise would not survive review. The
claim made here is narrower: that for policies in this fragment, all-combinations coverage
over the label categories is provably equivalent to mutation adequacy (Corollary 4), so an
adequacy question with a normally undecidable component reduces to a coverage question that
costs one pass over the suite. The criterion is old; the equivalence and the reason it holds
are what this document contributes.

**"Equivalent-mutant detection is a studied problem, and this proof is trivial."** Detecting
equivalent mutants in general programs is undecidable, and the literature accordingly
pursues partial methods: constraint-based reasoning, compiler-equivalence, coverage-based
heuristics. The result here is not a better method for that problem; it is the observation
that this policy language sidesteps it.

The argument is elementary but it is not vacuous, and an earlier draft of this document
overstated how little there was to it by describing the language as a product of finite
label domains. It is not: two components are sets, one predicate is a namespace wildcard,
and three components range over arbitrary strings, so the subject space is infinite and no
enumeration of it exists. What Theorem 1 establishes is that each predicate the language
offers induces finitely many classes *computable from the policy text*, and that a witness
can be constructed for each -- including for a wildcard pattern, which stands for infinitely
many capabilities. The contribution is that construction and the demonstration that a useful
policy language admits it, not the difficulty of the argument.

What survives those three concessions is: a stated fragment, an exactness result that makes
a reported mutation score meaningful rather than approximate, a witness showing the criterion
is independent of the structural coverage tooling already in use, an instrument that measures
the output criterion across three real policy ecosystems, and the empirical finding that the
criterion is nearly always already satisfied where decision domains are binary. The last of
those is a negative result, and it is reported as one.
