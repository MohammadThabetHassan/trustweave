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
- The mutation experiment has one decision-blind policy in it. A single correct prediction
  at p = 0.021 is evidence, not a validated predictor, and the operator set is syntactic.
- Rego extraction is 96%, not 100%, and the adapter's refusals are conservative by design,
  so the true figure could move in either direction by at most two files.

## Reproducing

```bash
python scripts/suite_coverage.py rego    <corpus> --json out.json   # needs opa on PATH
python scripts/suite_coverage.py kyverno <corpus> --json out.json
python scripts/suite_coverage.py cedar   <corpus> --json out.json
```

Corpora are pinned to exact commits in the `corpus` block of each artifact:
`docs/suite-coverage-{rego,kyverno,cedar}-v1.json`. The Rego corpus is Rego v0 and OPA 1.x
parses v1 by default, so the adapter retries with `--v0-compatible` rather than dropping the
file. Extraction logic is unit tested against transcribed AST fixtures and written manifests
in `tests/test_suite_coverage.py`, so the tests run in CI without opa or a network.
