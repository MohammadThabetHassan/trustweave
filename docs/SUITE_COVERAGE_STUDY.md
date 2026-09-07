# What published policy suites actually pin

`benchmark/orthogonality-witness` exhibits a policy suite that reaches 100% structural
coverage and still cannot detect its policy's default changing. That is a constructed
example. This study asks whether the same gap appears in the policy suites people publish
and depend on, across three ecosystems whose decision structures differ.

## The question

A policy decides over a finite domain. A suite either witnesses a given decision for a
given policy subject or it does not. A subject whose suite only ever witnesses one decision
is *blind*: the policy could be rewritten to return that decision unconditionally and every
test would still pass. Counting that is cheap, and unlike mutation score it is exact --
there is no sampling and no equivalent-mutant problem, because the domain is enumerable.

The interesting variable is the size of the decision structure, so the ecosystems were
chosen to differ along it:

| Ecosystem | Decision domain | What a subject is |
|---|---|---|
| Rego (Gatekeeper) | binary: violation set empty or non-empty | a `violation` rule, scoped to its file |
| Kyverno | `pass` / `fail` / `skip`, per rule type | a `policy/rule` pair |
| Cedar | binary `allow` / `deny`, over principal x action x resource | a policy set |
| XACML | four-valued: `Permit`, `Deny`, `NotApplicable`, `Indeterminate` | a policy, across its cases |

## Method

`scripts/suite_coverage.py` is the instrument; the three adapters beside it read one
ecosystem each and emit the same thing -- an observation is a decision, a subject, and the
test that pinned it.

The Rego adapter works on `opa parse --format json` output rather than source text, so it
sees what OPA sees. Suites there express a decision three ways, and the dominant one needs
a binding tracked: `results := violation with input as x` followed by `results[r]` (a
denial) or `count(results) == 0` (a permit). The assertion names a local variable, and only
the earlier assignment says which rule that variable holds the output of.

Kyverno states its expectation directly, so extraction is near total, but rule *type* has
to be resolved from the referenced policy. That resolution is not a detail -- see below.

Cedar labels every request, and additionally exposes a request space with product
structure, so the adapter records which `principal|action|resource` cells a suite witnesses
and how many it witnesses under both decisions.

Throughout, the adapters refuse rather than guess. `count(r) != 2` is a real assertion that
says nothing about whether the policy denied, so it is dropped. `result == expected_set` is
read as a denial only when the expected set is provably non-empty. OPA builtins are
excluded as subjects, taken from `opa capabilities --current` rather than a hand-kept list,
because `trace("...")` and `is_exempt(input)` are structurally identical one-argument calls.

## Extraction comes first

Every report prints its extraction rate before any summary, and suppresses the summary
below 80%. This is not ceremony. An earlier revision of the Rego adapter read 19% of its
corpus and reported that 8 of 10 suites tested a single outcome; at 96% extraction the same
corpus reports the opposite. The measured files are whichever ones an adapter understands,
which is not a sample of anything, and the artifacts name every file that yielded nothing
so the remainder can be audited rather than assumed uninteresting.

| Ecosystem | Files | Extraction | Decisions pinned |
|---|---|---|---|
| Rego | 51 / 53 | 96% | 994 |
| Kyverno | 494 / 495 | 100% | 1584 |
| Cedar | 24 / 24 | 100% | 78 |
| XACML | 59 / 59 | 100% | 65 |

The three unread files are named in the artifacts: one Rego suite is entirely commented
out, one asserts through a two-level helper where guessing would report a permit as a
denial, and one Kyverno manifest has no results block.

## Results

The measure asks two questions of each subject, and the gap between them is the finding.
*Blind* asks whether a suite ever witnesses a second decision. *Covers the domain* asks
whether it witnesses every decision the language admits.

| Ecosystem / domain | Values in domain | Subjects | Witness >1 | Cover the whole domain |
|---|---|---|---|---|
| Rego `violation_set` | 2 | 49 | 48 (98%) | 48 (98%) |
| Cedar | 2 | 23 | 21 (91%) | 21 (91%) |
| Kyverno `validate` | 3 | 328 | 305 (93%) | 15 (5%) |
| XACML | 4 | 21 | 17 (81%) | 1 (5%) |

**In a two-valued domain the two questions are the same question, and practitioners answer
it.** 91% to 98% of Gatekeeper and Cedar subjects witness both of their decisions. On such a
policy the measure is close to vacuous: it agrees with almost every suite it is shown, and
running it teaches a team nothing they had not already done.

**Once the domain is larger than binary the two questions separate sharply.** 93% of Kyverno
validate rules witness more than one result and 5% witness all three; 81% of XACML policies
witness more than one decision and one of twenty-one witnesses all four. The bar that a
binary domain clears by writing a single negative case is not cleared once there is a third
outcome to write.

That is the empirical form of the argument in `DECISION_CLASS_COVERAGE.md`: the criterion's
discriminating power scales with the decision structure, and the ecosystems in wide use
today mostly sit at the size where it discriminates least.

### What the 5% does and does not mean

It does not mean 95% of those suites are defective. Corollary 5 of the theory document is
exactly the caveat: an unwitnessed decision certifies a gap only when the policy can
actually return that decision. Kyverno's `skip` means a rule did not apply, and a rule that
always applies has no `skip` case to write. XACML's `Indeterminate` arises from evaluation
errors, which a policy may never produce. Neither can be checked from the suite alone -- it
needs the policy's range, which for these languages is not decidable.

So the honest reading is narrower than the table looks, and it is still useful. At `|D| = 2`
the measure raises almost nothing and cannot be used to prioritise review. At `|D| >= 3` it
raises almost everything, and each raised item is a specific named outcome a reviewer can
confirm or dismiss in one reading of the policy -- which is a work list, not a verdict.

### The exception that was verifiable

One Gatekeeper suite is blind on the stronger reading as well.
`gatekeeper-library/src/general/verifydeprecatedapi` has two tests and both assert
`count(results) == 0`, including `test_hpa_with_deprecated_api`, whose name says it should
produce a violation. Nothing in that suite fails if the constraint stops firing, which is
the fail-open direction for admission control. The next section shows it also catches none
of its mutants.

Four XACML policies and two Cedar policy sets witness a single decision; 23 Kyverno validate
rules do, 14 of them only `fail` and 9 only `pass`. Two were checked by hand:
`require-image-source/check-source` has exactly one expectation, `pass` on `goodpod01`, and
`restrict-pod-count/restrict-pod-count` exactly one, `fail` on `myapp-pod`.

## Does the measure predict anything?

The exactness results hold inside the policy fragment. Rego is outside it, so for that
corpus the measure is an observation rather than a theorem, and the question worth asking is
empirical: when it calls a suite blind, does that suite actually miss more faults?

`scripts/rego_mutation.py` answers it directly. It mutates each Gatekeeper policy with
single syntax-preserving edits -- flipping a comparison, dropping a negation, flipping a
boolean -- and runs that policy's own suite against every mutant. 48 of 49 policies scored,
625 mutants applied, 475 killed, an overall mutation score of 0.76.

Joined against the decision-coverage verdict for the same policies:

| | Policies | Mutation score |
|---|---|---|
| Decision-blind | 1 | 0.00 |
| Decision-covered | 47 | 0.50 - 1.00 (median 0.80) |

**The one suite the measure flagged catches none of its four mutants, and is the only zero
in the corpus.** Under the null hypothesis that blindness is unrelated to detection, the
chance that the flagged suite lands lowest of 48 is 1/48, p = 0.021. So the measure's single
prediction on this corpus was correct, and correct at conventional significance.

That is a narrow claim and the second half of the table is why. Decision coverage here is
*saturated*: 47 of 48 suites achieve it, while their mutation scores range from 0.50 to
1.00. The measure is silent about every suite in that range, including several that miss
half their mutants. In a binary decision domain it makes almost no predictions -- so it
cannot substitute for mutation testing there, and a project running both would learn almost
nothing from the first.

This is Corollary 5 of `DECISION_CLASS_COVERAGE.md` arriving from the other direction.
Decision coverage is necessary and not sufficient; in a two-valued domain the necessary part
is nearly always already satisfied, which leaves it carrying almost no information. The
measure earns its keep as the decision structure grows, and this corpus is the wrong place
to see that happen.

Two limits are worth stating plainly, and both are consequences of leaving the fragment.
Survivors cannot be separated from equivalent mutants, so 0.76 is a lower bound on suite
quality rather than an exact figure -- which is precisely what the fragment buys and Rego
does not. And the operator set is syntactic, so the number measures these suites against
these edits, not against all faults.

### Replicating the prediction where the domain is larger

One correct prediction is a result about one policy. `scripts/kyverno_mutation.py` repeats
the experiment where the decision domain is three-valued and the measure flags 23 validate
rules rather than one.

The design is case-control. Every blind validate policy is measured; the comparison group is
filled by walking the covered policies in name order until enough of them score. A mutant
edits the policy -- negating a condition operator, weakening a required value, turning a
conditional anchor into a required one, flipping a CEL quantifier or connective -- and the
policy's own suite is run against it by the Kyverno CLI. A policy yielding fewer than three
applicable mutants is skipped, because a score from one mutant describes the operator set.

**This experiment was run twice, and the first run is reported alongside the second.**

| Run | Blind | Covered | Blind median | Covered median | Difference | p (one-sided) |
|---|---|---|---|---|---|---|
| 1 | 5 | 25 | 0.33 | 0.43 | 0.064 | 0.33 |
| 2 | 9 | 40 | 0.50 | 0.625 | 0.149 | 0.043 |

The first run found nothing and was reported as a failure to replicate, with the reason
stated at the time: 108 of the selected policies yielded fewer than three mutants and were
skipped, so only 5 of 23 blind policies were measured at all. Inspecting the skipped set
showed why -- Kyverno's newer policies carry their logic in CEL expression strings, and the
generator only knew the older condition-block operators, so a policy whose entire rule is
one CEL expression had nothing to edit.

The second run adds those operators. Nothing about the outcome measure changed: the same
coverage verdict splits the arms, the same floor applies to both, the same CLI decides
whether a mutant is killed. What changed is how many policies could be measured.

**The direction is the one the hypothesis predicts and the gap is now marginally
significant.** Blind policies kill a median 0.50 of their mutants against 0.625 for covered
ones, and a permutation test puts that at p = 0.043 one-sided, so roughly 0.09 two-sided.

Three things bound it, and they matter more than the figure.

The operator set changed between the runs, which is a researcher degree of freedom. It was
changed for a reason stated before the second result was seen, and the direction of the
first result already matched, but a reader is entitled to weigh a p-value obtained after
adjusting the instrument less heavily than one obtained before.

Nine policies is a small arm. A one-sided p just under 0.05 from nine observations is
suggestive and not established; it would not survive a correction for the two experiments
run, and the two-sided reading does not clear 0.05 at all.

And this measures suites against these edits, not against real faults. Survivors cannot be
separated from equivalent mutants outside the fragment, so every score here is a lower bound
on suite quality rather than the exact figure the fragment permits.

The honest summary across both ecosystems: the measure's flags correlate with worse fault
detection, weakly, in the direction predicted, on samples too small to settle it.

### Is the relation graded, or only a flag?

If witnessing more decisions predicted detecting more faults, the measure could report a
quantity instead of a flag, which would be worth more to a team than a warning. That is a
testable claim and it does not hold on this data.

`scripts/decision_trend_test.py` joins every scored Kyverno policy to the number of
decisions its best-covered validate rule witnesses, and tests the ordered alternative with
a Jonckheere-Terpstra permutation test. All 49 scored policies join.

| Decisions witnessed | Policies | Median mutation score |
|---|---:|---:|
| 1 | 5 | 0.200 |
| 2 | 41 | 0.625 |
| 3 | 3 | 0.667 |

The medians rise monotonically, and the trend test puts that at **p = 0.157 one-sided**
(20,000 permutations, seed 0). **The ordered trend is not supported.** Almost all of the
separation is between one decision and two; going from two to three adds 0.04 of median
score across three policies. The same join reproduces the published blind-against-covered
contrast exactly -- 9 blind at median 0.5 against 40 covered at 0.625 -- so the two analyses
differ in what they ask, not in the data they read.

The reading that survives is narrower than the one worth hoping for: what the measure
detects is *blindness*, a suite that never writes a second outcome. It is not a graded
estimate of suite quality, and reporting it as one would overstate what was measured. Note
also that aggregating by the policy's best rule rather than by the recorded per-policy flag
makes the blindness contrast **larger** -- 5 blind at median 0.200 -- which suggests the
published flag dilutes the signal by counting a policy covered when only one of its rules
is.

### The one predictive result does not come from the policies the theory covers

The contrast above is the study's only evidence that the measure tracks fault detection:
blind Kyverno policies kill a mean 0.4534 of their mutants against 0.6024 for covered ones,
a difference of 0.149 at p = 0.043 one-sided. The exactness results the measure descends
from hold only inside the fragment of
[DECISION_CLASS_COVERAGE.md](DECISION_CLASS_COVERAGE.md), and section 4b there can now say
which policies those are. So the contrast can be stratified, and it should be, because a
pooled figure that mixes the policies a theory covers with the ones it does not is not
evidence about the theory.

`scripts/fragment_stratified_test.py` does it with the same statistic
`scripts/kyverno_mutation.py` uses -- a difference in group means under a one-sided
permutation of the labels -- so the pooled row reproduces the published number exactly
rather than reporting a differently-computed one beside it. All 49 scored policies carry a
verdict.

| Stratum | Policies | Blind | Covered | Difference | p (one-sided) |
|---|---:|---:|---:|---:|---:|
| All | 49 | 9 at 0.4534 | 40 at 0.6024 | +0.1490 | **0.043** |
| Inside the fragment | 41 | 4 at 0.5119 | 37 at 0.5779 | +0.0660 | 0.272 |
| Outside the fragment | 8 | 5 at 0.4067 | 3 at 0.9047 | +0.4981 | **0.018** (exact) |

**The association is confined to the eight policies outside the fragment.** Inside it,
where the criterion is exact and the theory applies, there is no detectable association:
the difference is 0.066 at p = 0.272, over 41 policies, which is the larger arm. Outside,
the difference is 0.498 and clears 0.05 on an exact test over all 56 splits.

Two readings are wrong and worth ruling out. This is **not** a refutation of Corollary 4.
That corollary requires witnessing every *cell* of the policy-relative quotient, and the
flag being stratified here records only whether a suite witnessed more than one of the three
Kyverno *decisions*. A policy's quotient has one cell per combination of its guards, which
is far more than three, so full decision coverage is a weak proxy for cell coverage and
Corollary 4 predicts nothing about it. What is measured here is the proxy, and the proxy is
what a practitioner would actually run.

Nor is it strong evidence that the proxy works outside the fragment. Eight policies is a
small stratum and it is not a random one: all eight are image or registry policies, the
group whose guards read a registry, and image-policy suites being weak is a plausible
alternative explanation for their low scores that has nothing to do with blindness.

What survives is a caveat on the study's own claim, and it is the honest consequence of
being able to ask the question. The p = 0.043 is a fact about a corpus that is 84% inside
the fragment, and the effect within that 84% is not distinguishable from zero. It should
therefore not be presented as evidence that the criterion tracks fault detection where the
criterion is exact. Taken with the threshold analysis below -- decision coverage on Kyverno
validate flags 95% of subjects and carries 0.268 bits -- the two point the same way: inside
the fragment the cheap proxy is nearly saturated, and a saturated verdict cannot correlate
with anything.

## Which threshold to set

Every result above uses one threshold: witnessing all `|D|` decisions. That choice is
natural from the theory, where full cell coverage is what Corollary 4 requires, and it is a
poor choice empirically. A threshold that flags almost every subject, or almost none,
cannot distinguish subjects whatever its standing in the proof.

The binary entropy of the flagged share measures that directly, in bits, and it is a
property of the corpus rather than an inference from a sample -- no sampling, no p-value.
`scripts/decision_threshold_analysis.py` computes it for every threshold on the corpora
already recorded, and writes
[`decision-threshold-analysis-v1.json`](decision-threshold-analysis-v1.json).

| Ecosystem / domain | \|D\| | Subjects | Threshold | Flags | Bits |
|---|---:|---:|---|---:|---:|
| Rego `violation_set` | 2 | 49 | k=2 *(published)* | 2.0% | 0.144 |
| Cedar | 2 | 23 | k=2 *(published)* | 8.7% | 0.426 |
| Kyverno `validate` | 3 | 328 | k=2 | 7.0% | **0.366** |
| Kyverno `validate` | 3 | 328 | k=3 *(published)* | 95.4% | 0.268 |
| Kyverno `mutate` | 3 | 88 | k=2 | 69.3% | **0.889** |
| Kyverno `mutate` | 3 | 88 | k=3 *(published)* | 100.0% | **0.000** |
| XACML | 4 | 21 | k=2 | 19.1% | 0.703 |
| XACML | 4 | 21 | k=3 | 57.1% | **0.985** |
| XACML | 4 | 21 | k=4 *(published)* | 95.2% | 0.276 |

**On Kyverno `mutate` the published threshold carries exactly zero bits.** It flags all 88
subjects, so it separates none of them: the verdict is a constant, and a constant is not a
measurement. Across the five domains with enough subjects to measure, the published
threshold is the most informative available one in **two**, and carries under 0.3 bits in
**four**.

Where the informative threshold sits is not `|D|` and not a fixed number. On XACML it is
three of four decisions, which splits the corpus 57/43 and carries 0.985 bits -- within 2%
of the most a binary verdict can carry. On the three-valued Kyverno domains it is two. The
rule that emerges is that the threshold should be chosen against the corpus, by the entropy
of the split it induces, rather than inherited from the proof.

This does not rescue the criterion as a substitute for mutation testing, and it is not
evidence that the entropy-chosen threshold predicts faults better -- that would need the
mutation experiment re-run per threshold, and at these arm sizes it would not settle
either. What it establishes is narrower and it is not an inference: the threshold the theory
hands you is, on four of five real corpora, close to the least informative one available,
and a better one is identifiable from the corpus without running any tests.

The honest consequence for the theory is that Corollary 4's requirement and a useful
empirical bar are different objects. Full cell coverage is what makes the mutation score
exact inside the fragment. Outside it, on the corpora people actually publish, it is mostly
a constant.

## Interpretation

The exactness results this measure descends from -- decidable equivalence, an exact kill
criterion, cell coverage deciding the mutation score -- hold over the policy language
defined and proved in [DECISION_CLASS_COVERAGE.md](DECISION_CLASS_COVERAGE.md). None of the
four ecosystems measured here is inside it: their subjects are arbitrary JSON, entity graphs
or XACML attribute categories, and their guards are general expressions, so no enumeration
exhausts them and equivalence is undecidable. Everything here is therefore an observation
about their suites rather than a proof about them, and the mutation experiment above is what
was done instead of a proof.

Taken together the two experiments say something more specific than either alone.

*The measure is not a substitute for mutation testing.* At `|D| = 2` it agrees with 91-98%
of suites while their mutation scores range from 0.50 to 1.00, so it is silent about exactly
the suites a team would want flagged.

*It is not noise either.* Its one flag on that corpus landed on the only suite that catches
none of its mutants, at p = 0.021.

*And its resolution is set by the decision structure, not by the policy's size.* The same
criterion that raises 2% of subjects at `|D| = 2` raises 95% at `|D| >= 3`. That is the
property the theory predicts and the reason it is worth stating: a team choosing a policy
language is also choosing how much a cheap output-coverage check can tell them, and the
languages in widest use are the ones where it can tell them least.

TrustWeave's own policy sits at the other end -- trust level times action class, where the
classes a suite must witness grow with the product -- and inside a language where the count
is exact rather than a lower bound. That is the case the criterion was built for, and no
public corpus of comparable agent-security policy suites exists yet to measure it against.

## An ecosystem the adapter could not read

A second binary-domain corpus was attempted and not used. Conftest and Konstraint policies
decide over `deny`, `warn` and `violation` rules, and their suites would have tested whether
the 91-98% saturation seen in Gatekeeper and Cedar is a property of binary domains or of
those two projects.

The adapter reads 35% of that corpus. Extending it to count a rule named directly --
`count(deny) == 0`, where conftest never binds the rule to a local first -- moved extraction
from 30% to 35% and is kept, because it is correct and applies everywhere. The remainder is
dominated by an idiom this study refuses on purpose: a test calls a helper the file defines,
which calls another helper, which counts. Reading it needs the two rules resolved and their
arguments substituted, and a wrong substitution would report a permit as a denial.

So the corpus is reported as unread rather than measured. A 35% sample would have been the
files the adapter happens to understand, which is the exact error that made an early version
of the Rego measurement support the opposite of its final conclusion. The saturation figure
therefore still rests on two ecosystems, and whether it generalises further is open.

## Threats to validity

- These are curated upstream libraries, which are plausibly better tested than private
  policy. The direction of that bias is toward under-reporting blindness.
- Blindness is a property of a suite as written. It is not proof of a defect in the policy,
  only that the suite could not detect one class of defect.
- Kyverno subjects that name no rule are attributed to `policy/*`, which merges rules of a
  multi-rule policy. 5 subjects could not have their type resolved at all.
- The Cedar corpus is 24 files and 78 requests, and the XACML one 21 policies over 59 cases.
  Both carry wide error bars, and the XACML figure rests on a single library's multi-case
  suites -- the OASIS conformance material is one case per language feature and measuring it
  would answer a different question.
- The Gatekeeper mutation experiment has one decision-blind policy in it, and the Kyverno
  replication nine. A one-sided p of 0.043 from nine observations, obtained after widening
  the mutation operator set, is suggestive rather than established, and does not survive a
  correction for the two experiments run. Nothing here supports a general claim that the
  measure predicts fault detection; it supports the weaker claim that the two point in the
  same direction.
- Rego extraction is 96%, not 100%, and the adapter's refusals are conservative by design,
  so the true figure could move in either direction by at most two files.

## Reproducing

```bash
python scripts/suite_coverage.py rego    <corpus> --json out.json   # needs opa on PATH
python scripts/suite_coverage.py kyverno <corpus> --json out.json
python scripts/suite_coverage.py cedar   <corpus> --json out.json
```

The two analyses added after the corpora were measured need neither a corpus nor a CLI.
They read the committed artifacts, so anyone with the repository can reproduce them:

```bash
python scripts/decision_threshold_analysis.py --json docs/decision-threshold-analysis-v1.json
python scripts/decision_trend_test.py --json docs/decision-trend-test-v1.json
```

`tests/test_decision_threshold_analysis.py` pins every figure they produce that this
document quotes, including the zero-bit result and the unsupported trend, and asserts the
committed artifact still equals a fresh computation.

One analysis does need a corpus, because it reads policies rather than suites. Fragment
membership -- which of these XACML policies lie inside the decidable fragment of
[DECISION_CLASS_COVERAGE.md](DECISION_CLASS_COVERAGE.md), reported in section 4b there -- is
measured by:

```bash
python scripts/fragment_membership.py xacml   <corpus> --only-measured docs/suite-coverage-xacml-v1.json
python scripts/fragment_membership.py cedar   <corpus> --only-measured docs/suite-coverage-cedar-v1.json
python scripts/fragment_membership.py kyverno <corpus> --only-measured docs/kyverno-mutation-v1.json
python scripts/fragment_stratified_test.py --json docs/fragment-stratified-test-v1.json
```

The stratified test needs no corpus, only the committed artifacts.
`tests/test_fragment_membership.py` works on transcribed policies and those artifacts, so
it runs in CI without a corpus or a network, and it pins the pooled figure so the strata
stay comparable with the published claim.

Corpora are pinned to exact commits in the `corpus` block of each artifact:
`docs/suite-coverage-{rego,kyverno,cedar}-v1.json`. The Rego corpus is Rego v0 and OPA 1.x
parses v1 by default, so the adapter retries with `--v0-compatible` rather than dropping the
file. Extraction logic is unit tested against transcribed AST fixtures and written manifests
in `tests/test_suite_coverage.py`, so the tests run in CI without opa or a network.
