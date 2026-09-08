# Decision-class coverage: the fragment, and what is exact within it

`scripts/policy_mutation.py` reports a mutation score without sampling and without a manual
equivalent-mutant audit. That is not a better heuristic; it is a consequence of the policy
language being restricted enough that the relevant questions are decidable. This document
states the restriction, proves what follows from it, and marks where it stops holding.

Every claim here is checked by `tests/test_decision_class_theory.py`, which verifies the
theorems by exhaustive enumeration against the shipped policy and the real mutant set rather
than restating them, and by `tests/test_combining_function_independence.py`, which verifies
the abstract form of section 4b over an infinite subject space under four different
evaluation rules.

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
at most `2^|G_P|` classes. Capability matching is existential over (named pattern, subject
capability), so only the *subset of named patterns some capability matches* matters: at most
`2^|K_P|` classes. Subjects agreeing on every component agree on every predicate, hence
match the same rules, hence receive the same decision. []

**The two set-valued terms are bounds and not counts, and an earlier version of this proof
claimed otherwise.** It asserted that each of the `2^|K_P|` subsets "is witnessed, since a
pattern `n.*` is matched by `n.w` for any `w`". That is false when patterns nest. Every
capability matching `net.http` also matches `net.*`, so on a policy naming both there is no
subject at all whose capabilities match `net.http` and not `net.*`: one of the four subsets
is occupied by nothing, and the subset `{net.http}` induces the same predicate answers as
`{net.*, net.http}`. Three classes exist where the proof claimed four.

The same holds for purpose tags for a different reason. A policy whose only purpose
predicate is "intersects `{a, b}`" cannot tell `{a}` from `{b}` from `{a, b}`: one class,
not three. There the collapse comes from the *predicate* being coarser than the subsets, not
from the values subsuming one another.

`witness_space()` now keeps one witness per achievable capability signature rather than one
per subset, which is what makes the capability term a count of realisable classes.
`tests/test_decision_class_theory.py` pins both counterexamples, including that disjoint
patterns still give a class each, so the correction cannot be mistaken for deduplicating
indiscriminately.

**And the corrected construction is certified by a solver rather than by this paragraph.**
`scripts/verify_witness_space.py` encodes the matching rule in SMT -- a final-wildcard
pattern as a string prefix, an exact pattern as equality -- and asks Z3, for every candidate
signature over a set of named patterns, whether any capability set realises it. The
construction must produce exactly the achievable ones: no unachievable signature, or it
invents a class no subject occupies, and none missing, or the quotient is incomplete and
Corollary 4's premise is unreachable. It agrees on all eight pattern sets checked, recorded
in [`witness-space-verification-v1.json`](witness-space-verification-v1.json):

| Named patterns | Candidate signatures | Achievable |
|---|---:|---:|
| `net.*` | 2 | 2 |
| `net.*`, `net.http` | 4 | **3** |
| `net.*`, `fs.*` | 4 | 4 |
| `net.http`, `net.https` | 4 | 4 |
| `net.*`, `net.http`, `net.http.get` | 8 | **5** |
| `net.*`, `fs.*`, `net.http` | 8 | **6** |
| `a`, `b`, `c` | 8 | 8 |

The same tool quantifies the purpose collapse. Over named tags `{a, b}` with a single rule
naming both, four subsets yield two achievable signatures; with two rules naming one tag
each, four subsets yield four. The predicate, not the value set, decides how much of the
product is real. This is the step the proof got wrong, so it is the step that is machine
checked.

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

### What the harness enumerates is a refinement of the quotient

`cells()` returns the product of the per-attribute witness spaces. That is a *refinement* of
`S/~P`, not the quotient itself: distinct cells can answer every predicate of every rule
identically, and when they do they are one class. The purpose example above is exactly that,
and it is not a corner case -- on a policy whose rules constrain only `trusted` and `read`,
the product enumerates all three trust levels and all four action classes where the policy
distinguishes two of each, so 48 cells stand for 16 classes.

The distinction matters, and it cuts differently for different results.

**Soundness carries over.** `[[P]]` is constant on each class of `~P` by Theorem 1, so it is
constant on each cell of any refinement of it. Theorem 3 and Corollary 4 below quantify over
cells and are therefore true as stated: a suite witnessing every cell witnesses every class,
and the kill criterion is a set intersection either way. Nothing in the reported scores
depends on the difference.

**Necessity carries over as stated, but not as it is easy to read.** The converse in
Corollary 4 is about *semantic* mutants -- arbitrary functions from cells to decisions -- and
a function may differ at one cell whatever the cells are, so the argument and the test that
checks it are sound on a refinement. Read instead as a claim about policies, it is not. If
two cells belong to one class of `~P`, then **no policy the language can express differs at
one of them and not the other**, so an unwitnessed cell whose twin is witnessed admits no
expressible surviving mutant. The distinction is between what the operator set could in
principle realise and what the language can say, and only the second needs the quotient.

That distinction was nearly lost twice: once by a proof step claiming each capability subset
is occupied, and once by an earlier draft of this very paragraph, which said flatly that
tightness fails on a refinement. It does not. What fails is the policy-level reading, and the
test in `tests/test_decision_class_theory.py` checks the semantic one, which is the weaker
claim and the true one.

Why the harness keeps the refinement rather than quotienting: a mutant is a different
policy, so its predicate signatures are different objects, and quotienting each side
separately would compare two policies over two different domains. Theorem 2's own
requirement is the *common* refinement of `~P` and `~Q`, and the product of the witness
spaces is one -- computed identically for reference and mutant, since the harness refuses a
mutant that names a value the reference does not. Quotienting is available where a single
policy is being described, and `predicate_signature()` is what computes the class of a cell.

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
non-equivalent mutant, for any mutation operator set whatsoever. The argument has one step
that is easy to skip and is the step doing the work. A non-equivalent mutant `M` has
`Delta(P, M)` non-empty by the definition of non-equivalence, so `[[P]]` and `[[M]]` differ
at some subject `s`. Every guard `M` can state is a guard over the same finite vocabulary as
`P`'s, so the cell set `S` -- the product of the per-attribute witness spaces -- separates
whatever `M` can separate, and `[[M]]` is constant on each cell. `Sigma` therefore has a case
at some `s'` in the same cell as `s`, where the two still differ, and Theorem 3 kills `M`.
The mutation score is 100% by construction rather than by measurement.

That step is why the harness enumerates the refinement rather than the quotient. Coverage of
`~P` alone would *not* suffice: `Delta(P, M)` is a union of classes of `~P` intersect `~M`,
not of `~P`, so a mutant drawing a distinction `P` does not can differ inside a class the
suite witnessed elsewhere.

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

## 4b. What the proofs actually use, and which languages have it

Everything above is stated for first-match evaluation over the label language of section 1,
and that is narrower than the proofs require. The arguments use exactly two properties, and
neither mentions first-match or any particular component:

**(i) The guards refine the subject space finitely, with computable witnesses.** For any
finite tuple of guards `g_1..g_n` drawn from the language, the map
`s |-> (g_1(s),...,g_n(s))` has finite image, and for each truth vector actually achieved a
subject realising it is constructible *from the guards' own syntax*. Call such a family
**finitely refining**.

**(ii) The decision is a function of the guard outcome vector.** Each guard reports one of
a finite outcome set `V`, and there is some `c : V^n -> D` with
`[[P]](s) = c(g_1(s),...,g_n(s))`.

`V = {true, false}` for a first-match policy. It is not always two-valued: an XACML guard
also reports *indeterminate* when a required attribute is absent, and that outcome is what
produces the `Indeterminate` decision, so for XACML `V` has three values. Nothing in the
argument depends on `|V|`, only on its being finite.

**Theorem 1b (the results are combining-function independent).** Let `P = (<g_i>, c)` be any
policy whose guards come from a finitely refining family and whose decision satisfies (ii),
over any subject space, finite or infinite. Then `S/~P` is finite with at most `|V|^n`
classes, `[[P]]` is constant on each class, a witness for each is computable, and Theorems 2
and 3 and Corollaries 4 and 5 hold verbatim with "cell" read as "achieved outcome vector".

*Proof.* `~P` is the kernel of `s |-> (g_i(s))_i`, which is finite by (i); `[[P]] = c` composed
with that map, so it is constant on each class by (ii). Every later argument consults only
the finite class set, the decision on each class, and a witness per class, all of which (i)
and (ii) supply. No step uses the shape of `c`. []

This matters because `c` is where the real languages differ, and they differ only in `c`:

| Language | `c` on the guard outcome vector | `D` |
|---|---|---|
| TrustWeave | decision of the first true guard, else the default | 3 |
| Cedar | `Deny` if any `forbid` guard holds; else `Allow` if any `permit` does; else `Deny` | 2 |
| Kyverno | `fail` if a rule's pattern is violated; `pass` if all match; `skip` if preconditions exclude | 3 |
| XACML | the chosen combining algorithm -- deny-overrides, permit-overrides, first-applicable | 4 |
| Rego (`violation`) | non-empty iff any `violation` guard holds | 2 |

Every one of these is a function of the outcome vector, so **(ii) is satisfied by all
five**.
`tests/test_combining_function_independence.py` checks this by construction rather than by
assertion: it builds one guard family over an infinite subject space -- arbitrary strings,
with set membership and a final-wildcard namespace pattern -- and verifies Theorem 1b,
Theorem 2, Theorem 3, Corollary 4 and the tightness result under first-match, Cedar's
forbid-overrides, Kyverno's any-rule-fails, and a four-valued XACML deny-overrides.
Hypothesis samples the infinite space, so the finite witness set is shown to account for
subjects the construction never named.

### So the boundary is (i), not the evaluation rule

What separates the languages is whether their *guards* are finitely refining. The dividing
line is whether a guard's induced partition is determined by the policy text:

**Inside.** Equality or set membership against literals in the policy; a final-wildcard
namespace pattern; a comparison against a literal threshold, which splits the space in two
however large the ordered domain is; bounds over a declared taxonomy. Each names a finite
number of sets, and a witness for each is readable off the syntax.

**Outside.** A guard whose partition depends on data absent from the policy text. Transitive
membership over an entity store of unbounded depth, so the answer is a property of the store
rather than of the subject. A pattern taken from the input rather than the policy. An
arbitrary builtin over a whole document. These are why Rego generally falls outside: its
guards may call any builtin over `data` and `input`, and Theorem 6 below is the limit case.

### How much of a real ecosystem is inside

A characterisation with no measurement beside it invites the reader to assume the answer is
"almost none". `scripts/fragment_membership.py` measures it, one adapter per ecosystem,
reading *policies* rather than the test suites that
[SUITE_COVERAGE_STUDY.md](SUITE_COVERAGE_STUDY.md) reads, at the commits that study pins.

Two scopes are measured, because they answer different questions. The **joined** scope is
the policies a suite study could also score, and it is what the stratified test in
[SUITE_COVERAGE_STUDY.md](SUITE_COVERAGE_STUDY.md) needs; it is small because measuring
decision coverage takes a suite with more than one case. The **whole-corpus** scope is every
policy the corpus holds, which is the honest scope for asking how much of an ecosystem the
fragment covers, since membership is decided from policy text and needs no suite at all.

| Ecosystem | Policies | Inside | Outside | Undetermined | Share inside |
|---|---:|---:|---:|---:|---:|
| *Whole corpus* | | | | | |
| XACML | 548 | **526** | 22 | 0 | 96.0% |
| Kyverno | 235 | **205** | 30 | 0 | 87.2% |
| Cedar | 22 | **22** | 0 | 0 | 100.0% |
| **Total** | **805** | **753** | **52** | **0** | **93.5%** |
| *Joined to a suite study* | | | | | |
| XACML | 21 | **15** | 6 | 0 | 71.4% |
| Kyverno | 49 | **41** | 8 | 0 | 83.7% |
| Cedar | 22 | **22** | 0 | 0 | 100.0% |

**Nothing is undetermined in any ecosystem at either scope**, so each figure is a verdict on
the whole corpus rather than on the part an instrument happened to understand. The joined
scope is a subset of the wide one and every verdict agrees between them, which is what makes
the stratified test's arms readable against this table. Artifacts, all now carrying the
pinned commit of the corpus they read --- which the first three did not, leaving the corpus
of the fragment measurement named only in prose:
[xacml](fragment-membership-xacml-v1.json), [kyverno](fragment-membership-kyverno-v1.json),
[cedar](fragment-membership-cedar-v1.json),
[xacml wide](fragment-membership-xacml-wide-v1.json),
[kyverno wide](fragment-membership-kyverno-wide-v1.json),
[cedar wide](fragment-membership-cedar-wide-v1.json).

Widening the corpus took two corrections to the instruments, and both were the same mistake
in different languages: an allowlist of *names* where the criterion is about *kinds*.

- **XACML** names a function `<type>-<family>`, and it is the family that decides
  membership -- `integer-greater-than` and `time-greater-than` both compare a designator
  against a literal and both split the subject space at that literal. The conformance corpus
  exercises **182 function names** the name-enumerated allowlist did not carry, and all but
  one belong to a family it already accepted for some other datatype. The exception is
  `xpath-node-count`, which reads the request's `Content` and is outside for the same reason
  an `AttributeSelector` is. Deciding by family moved the wide count from 131 inside with
  396 undetermined to 526 inside with none.
- **13 XACML policies state no predicate at all** -- no `Match`, `Condition`, `Apply` or
  `VariableDefinition` element anywhere. Those are not unjudged: a policy stating no
  predicate induces a quotient with a single class, which is the fragment's strongest case
  rather than a gap in it. The instrument now decides that by the presence of guard-bearing
  elements rather than by whether its function scan came back empty, because the two causes
  of an empty scan -- a policy with no guards, and a guard the scan could not read -- must
  not be conflated.
- **Kyverno** needed `resource.List` and `resource.Post` added to the external calls, since
  both reach the API server exactly as `resource.Get` does; `jsonpatch.escapeKey` and
  `image(...).registry()` recognised as total functions of the request, the latter parsing an
  image reference already in the admission review rather than querying a registry;
  `generator.Apply` recognised as an *effect* rather than a guard; and the names a policy's
  own `context` entries bind treated as request-derived -- sound because an external context
  source returns `outside` before that point is reached, so any surviving binding is a
  JMESPath over the request, whose own roots are screened the same way.

Every verdict in the joined scope is unchanged by all of this, which is the check that
matters: the widening added decisions where the instruments had refused, and moved none that
they had already made.

What is outside is outside for one kind of reason in each ecosystem, and it is always the
same kind: a guard that reads something the policy does not contain.

- **XACML**: all six are an `AttributeSelector`, which puts an arbitrary XML document in the
  subject, so no witness for the XPath predicate is constructible from the policy text.
- **Kyverno**: a `context` entry that queries the cluster or a registry, or a CEL call that
  does -- and `now()`, which makes the guard depend on when it ran rather than on the
  request. Kyverno's built-in `images` variable is *not* one of these: it is parsed from the
  container references already in the request, and the adapter distinguishes it from the
  `imageRegistry` context that does query a registry.
- **Cedar**: nothing is outside, and that is not a fact about this corpus. Cedar has no
  construct for reading data the request does not carry -- no HTTP, no cluster, no clock --
  and it ships an SMT-based analysis tool because it was designed to admit exactly this kind
  of reasoning. The fragment is one statement of what that design buys.

The debatable judgement is Cedar's `principal in Group::"admins"`, whose truth depends on
the entity store rather than on the policy. It is admitted: the predicate has two outcomes,
the policy names the parent entity, so a store realising either outcome is constructible,
and the store is an input to authorization rather than something fetched during it. A
hierarchy of unbounded depth does not change that, because the outcome is all the policy
observes. The adapter records that reasoning next to the rule.

Each adapter refuses rather than guesses, and that discipline earned its keep three times
while these were written, each time by reversing a number that had looked settled.

1. The XACML adapter first read only `FunctionId`, missing every `Target` match, which XACML
   names with `MatchId`. It reported a policy whose only guard is a `string-equal` target as
   naming no function at all, and the corrected scan moved the count from 14 inside to 6.
2. That left nine policies undetermined on one function, `string-regexp-match`, which had to
   be judged rather than assumed. It qualifies: XACML's regexp is the XML Schema one, with
   no backreferences, so the pattern denotes a regular language and a witness for either
   side of the split is constructible. The figure became 15.
3. The Kyverno corpus ships most policies three times -- a classic `ClusterPolicy`, a `-cel`
   variant, and a `-vpol` `ValidatingPolicy` -- and **38 of the 49 policies the mutation
   experiment scored exist at more than one path**. Keying on the file name picked whichever
   sorted first, which joined a verdict about one file to a mutation score for another. The
   adapter now resolves policies through each `kyverno-test.yaml` exactly as
   `scripts/kyverno_mutation.py` does, which is what makes the join sound.

Three limits belong with the figures. These are curated upstream test corpora, not deployed
policy. Membership is a property of the guards, so a policy inside the fragment gets the
exactness results for *its own* decision structure; it does not make its language decidable,
which Theorem 6 rules out. And **no equivalent measurement is claimed for Rego**: it is the
case Theorem 6 describes, since its guards may call any builtin over `data` and `input`.

The measurement also makes a stratified reading of the study's one predictive result
possible, and that reading is not favourable. It is in
[SUITE_COVERAGE_STUDY.md](SUITE_COVERAGE_STUDY.md).

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

### What the approximation costs, measured

"Normally answers approximately" is the load-bearing comparison in this section and it was
never quantified, which left the value of exactness to the reader's imagination.
`scripts/estimator_comparison.py` measures it on the shipped policy, where the exact answer
is available to compare against, and writes
[`estimator-comparison-v1.json`](estimator-comparison-v1.json).

Of 38 generated mutants, **16 are provably equivalent -- 42.1%**. A tool that cannot decide
equivalence has two options: ask a human to triage every survivor, or leave the equivalent
mutants in the denominator. The second is what an automated pipeline does, and it costs:

| Suite | Exact score | Without equivalence detection | Understated by |
|---|---:|---:|---:|
| `default-scenarios` | 63.6% | 36.8% | 26.8 pt |
| `adversarial-scenarios` | 36.4% | 21.1% | 15.3 pt |
| `coverage-matrix-scenarios` | **100.0%** | **57.9%** | **42.1 pt** |

The last row is the one to keep. That suite witnesses every cell, so by Corollary 4 it kills
every non-equivalent mutant and its adequacy is complete by construction. A pipeline without
the fragment reports it as 57.9%, and a team reading that number would go looking for the
42% of mutants that "survived" -- all sixteen of which are provably indistinguishable from
the original for every subject the language can express. The error has one sign: undetected
equivalents inflate the denominator, so the score is always understated, never flattered.

Sampling costs separately. Where the mutant set is too large to run whole, a tool scores a
random sample; here the true kill set is known, so the error is computed rather than
simulated. Against the 63.6% suite, a sample of 4 of the 22 live mutants is off by 0.19 on
average and by more than ten points in **every** sample; at 12 it is off by more than ten
points in 38% of samples; only at 20 of 22 does it reliably come within ten points.

Neither cost is exotic and neither is a criticism of any tool. They are the price of the
question being undecidable, which is exactly what the fragment removes -- and the size of
that price is what makes the removal worth stating.

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

**Theorem 6.** If a guard may be an arbitrary *total* computable predicate, presented as a
program, policy equivalence is undecidable.

*Proof.* Reduce from the halting problem. Given a machine index `e`, let

    g_e(s) = 1 if e halts on input 0 within |s| steps, else 0

where `|s|` is the length of a fixed encoding of the subject. `g_e` is total -- the
simulation is cut off after `|s|` steps -- and computable, and a program for it is computable
from `e`. Let `P_e` have the single rule "if `g_e(s)` then allow" with default deny, and let
`Q` have no rules and default deny. Subjects of every length exist, so some subject satisfies
`g_e` exactly when `e` halts on `0`; hence `[[P_e]] = [[Q]]` exactly when `e` does not halt
on `0`. []

Insisting on *total* guards is what makes this say something. With partial guards the
conclusion also follows from Rice's theorem, the indices of empty domain being a non-trivial
index set, but then the guards are not predicates at all and the theorem is about a language
nobody would ship.

**Which clause fails is the interesting part.** Each `g_e` induces exactly two classes, so
finiteness is not what the fragment buys. What fails is witness computability: no witness for
the class `g_e(s) = 1` can be computed from the guard's syntax, because whether that class is
occupied is the halting question. The results above rest on witness construction, which is
why [`verify_witness_space.py`](../scripts/verify_witness_space.py) certifies the
construction and not the bound.

So the boundary is not expressiveness in the loose sense, and it is easy to misplace it. A
regular expression against a pattern the policy *writes down* stays inside: the pattern
denotes a regular language, so it splits subjects two ways and a witness for either side is
constructible -- which is exactly why the XACML measurement in section 4b judges
`string-regexp-match` admissible rather than refusing it. What leaves the fragment is a guard
whose partition is not fixed by the policy text: a pattern or threshold taken from the
*input* rather than written in the policy, a lookup of state the request does not carry, an
arbitrary builtin over a whole document, or a reading of the clock. That is the boundary to
watch as the language grows, and it is a design constraint on the language rather than a
limitation of the tool.

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
the output criterion across four real policy ecosystems, and two negative results reported as
such -- that the criterion is nearly always already satisfied where decision domains are
binary, and that what it detects is blindness rather than a gradient.

Two things were added after those concessions were written, and both narrow the gap between
what is proved and what was measured. Section 4b locates the obstacle: the proofs never use
first-match, so an ecosystem is excluded only by its guards, not by its evaluation rule or
the size of its decision domain -- which is checked under Cedar's, Kyverno's and XACML's
combining rules rather than argued. And the threshold analysis in the study shows that the
bar this document hands a practitioner, full cell coverage, is on four of five real corpora
close to the least informative available, carrying literally zero bits on one of them. That
is a criticism of the criterion's practical form, it is arithmetic rather than inference, and
it belongs here rather than in a reviewer's report.
