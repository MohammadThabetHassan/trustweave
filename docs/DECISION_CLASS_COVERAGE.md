# Decision-class coverage: the fragment, and what is exact within it

`scripts/policy_mutation.py` reports a mutation score without sampling and without a manual
equivalent-mutant audit. That is not a better heuristic; it is a consequence of the policy
language being restricted enough that the relevant questions are decidable. This document
states the restriction, proves what follows from it, and marks where it stops holding.

Every claim here is checked by `tests/test_decision_class_theory.py`, which verifies the
theorems by exhaustive enumeration against the shipped policy and the real mutant set rather
than restating them.

## 1. The fragment

Fix three finite label sets:

- trust levels `T = {trusted, conditional, untrusted}`
- action classes `A = {read, write, sensitive, external}`
- decisions `D = {allow, deny, require_approval}`

The **subject space** is `S = T x A`, with `|S| = 12`. A **policy** `P` is a finite ordered
sequence of rules `r_1 ... r_n` together with a default decision `d_0 in D`. Each rule is a
triple `(G_T, G_A, d)` with `G_T` a subset of `T`, `G_A` a subset of `A`, and `d in D`.

The semantics is first-match:

```
[[P]](t, a) = d_i   where i is least with t in G_T(r_i) and a in G_A(r_i)
[[P]](t, a) = d_0   if no such i exists
```

Two properties matter and both are immediate. `[[P]]` is **total**: every subject receives a
decision, because `d_0` is mandatory -- this is the fail-closed default the tool enforces.
And `[[P]]` is a function `S -> D` and nothing more: no rule may consult anything outside
`(t, a)`.

That last restriction is the whole fragment. It is what the rest of this document trades on,
and section 6 is what it costs.

## 2. Finite characterisation

**Theorem 1.** Every policy in the fragment is completely characterised by its **decision
vector** `v(P) = <[[P]](s)>_{s in S} in D^S`. The space of distinguishable behaviours is
finite, with `|D^S| = 3^12 = 531441` elements.

*Proof.* `[[P]]` is a total function `S -> D` by section 1, and `v(P)` is that function
tabulated. Nothing about `P` beyond `[[P]]` is observable to a scenario expressed in these
labels, since such a scenario supplies only a subject `s in S`. []

`decision_map()` computes `v(P)` in `|S|` evaluations.

## 3. Equivalence is decidable

**Theorem 2.** For policies `P, Q` in the fragment, `P` and `Q` are semantically equivalent
if and only if `v(P) = v(Q)`. Equivalence is decidable in `|S|` evaluations of each policy.

*Proof.* Immediate from Theorem 1: equivalence means agreement on every subject, and `v`
tabulates exactly that. []

This is what removes the equivalent-mutant problem. In general mutation testing, deciding
whether a surviving mutant is equivalent to the original is undecidable, so tools either
approximate the score or a human inspects survivors. Here a mutant is discarded as
equivalent precisely when its decision vector equals the reference vector, which is a
comparison of two 12-entry tables. The reported score has no equivalent mutants hiding in
its denominator, and this is a fact about the language rather than a claim about the tool.

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

**Corollary 5 (decision-class coverage is necessary, not sufficient).** Let a suite's
**decision classes** be `{d : (s, d) in Sigma}`. If some decision `d` is never expected, then
no mutant can be killed by a case expecting `d`, so a policy differing from `P` only by
returning `d` somewhere unwitnessed survives. Witnessing every decision class is thus
necessary for full detection. It is not sufficient: a suite may expect all three decisions
while witnessing only three of the twelve cells, and Theorem 3 then leaves nine cells
undefended.

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

## 7. Where the fragment ends

**Theorem 6.** If rule guards may contain arbitrary computable predicates over an unbounded
subject space, policy equivalence is undecidable.

*Proof sketch.* Let `e` be an arbitrary program. Build policies over subjects encoding
inputs: `P_e` returns `deny` on subject `x` when `e` halts on `x` and `allow` otherwise, and
`Q` returns `allow` everywhere. Then `P_e` is equivalent to `Q` exactly when `e` halts on no
input, which is not decidable. Equivalently, semantic equivalence to a fixed policy is a
non-trivial property of the guard programs' extensions, so Rice's theorem applies. []

So every exactness claim above is a claim about the finite-label fragment, and none of it
transfers to policy languages with open subject spaces. Rego, Cedar and Kyverno all sit
outside it: their subjects are arbitrary JSON or entity graphs, their guards are general
expressions, and their decision domains -- while small -- are reached through predicates
that no enumeration can exhaust. The measurement in `docs/SUITE_COVERAGE_STUDY.md` is
therefore an *observation* about those suites, not a proof about them: it reports which
decisions a suite pins, which is well defined everywhere, while the exactness results here
require the fragment.

TrustWeave's own policy is inside the fragment by construction, which is the reason its
adequacy can be computed rather than estimated. Keeping it there is a design constraint
rather than an accident, and it is enforced twice: `scripts/policy_mutation.py` refuses a
policy whose rules constrain data classification, capabilities, identifiers or purpose,
because `decision_map` does not range over those and would report two distinguishable
mutants as equivalent; and `tests/test_decision_class_theory.py` fails if the shipped policy
ever leaves the fragment.

The `policy/v1alpha2` schema admits exactly such rules. A policy using them is still finite
-- the results above generalise to any product of finite label domains, with `S` the larger
product -- but the harness as written enumerates only trust x action, so it must refuse
rather than silently measure a subspace and report the result as exact.

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

**"Equivalent-mutant detection is a studied problem, and this proof is trivial."** The proof
is trivial -- deliberately. Detecting equivalent mutants in general programs is undecidable,
and the literature accordingly pursues partial methods: constraint-based reasoning,
compiler-equivalence, coverage-based heuristics. The result here is not a better method. It
is the observation that a policy language restricted to finite label products makes the
question decidable outright, which converts a research problem into a table comparison. The
contribution is the restriction and the demonstration that a useful policy language fits
inside it, not the difficulty of the argument.

What survives those three concessions is: a stated fragment, an exactness result that makes
a reported mutation score meaningful rather than approximate, a witness showing the criterion
is independent of the structural coverage tooling already in use, an instrument that measures
the output criterion across three real policy ecosystems, and the empirical finding that the
criterion is nearly always already satisfied where decision domains are binary. The last of
those is a negative result, and it is reported as one.
