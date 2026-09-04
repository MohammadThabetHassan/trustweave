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

The three unread files are named in the artifacts: one Rego suite is entirely commented
out, one asserts through a two-level helper where guessing would report a permit as a
denial, and one Kyverno manifest has no results block.

## Results

| Ecosystem / domain | Subjects | Witness >1 decision | Blind |
|---|---|---|---|
| Rego `violation_set` | 49 | 48 (98%) | 1 |
| Rego `boolean` | 2 | 2 (100%) | 0 |
| Kyverno `validate` | 328 | 305 (93%) | 23 |
| Kyverno `mutate` | 88 | 27 (31%) | 61 |
| Kyverno `generate` | 9 | 0 (0%) | 9 |
| Cedar | 23 | 21 (91%) | 2 |

**Suites for policies with a genuine two-sided decision are well covered.** The
straightforward hypothesis -- that published suites routinely test one side -- does not
hold. Between 91% and 98% of validate, violation and authorization subjects witness both
outcomes. Practitioners writing enforcement policy do test both directions.

**The mutate and generate rows are not a finding of poor testing.** A mutate rule is tested
by comparing against a patched resource: `pass` means the patch matched, and `fail` is not
an outcome a correct suite produces. Their low numbers are an artifact of the measure being
applied to a domain where it does not mean what it means elsewhere.

That artifact is the methodological result. Measured without resolving rule type, this
corpus reports 94 of 430 subjects blind -- 22%, a headline number. Resolving type moves the
comparable figure to 23 of 328 validate rules, 7%. **A decision-coverage measure that
ignores the ecosystem's decision structure overstated the problem threefold.** Any adapter
for a new ecosystem has to establish which of its outcomes are genuinely dual before its
percentages mean anything.

## What the measure did find

23 Kyverno validate rules are blind, in both directions:

- **9 witness only `pass`.** If the rule silently stopped matching, its tests still pass.
  `require-image-source/check-source` has exactly one expectation: `pass` on `goodpod01`.
- **14 witness only `fail`.** If the rule rejected everything, its tests still pass.
  `restrict-pod-count/restrict-pod-count` has exactly one expectation: `fail` on `myapp-pod`.

One Gatekeeper suite is blind. `gatekeeper-library/src/general/verifydeprecatedapi` has two
tests and both assert `count(results) == 0` -- including `test_hpa_with_deprecated_api`,
whose name says it should produce a violation. Nothing in that suite fails if the constraint
stops firing entirely, which is the fail-open direction for admission control.

Two Cedar policy sets witness only `allow`. Across the Cedar corpus, 33 distinct request
cells are witnessed and 22 of them (67%) under both decisions -- the lowest figure in the
study, and the one measured over a product-structured request space rather than a flat
binary. The corpus is small enough that this is a direction to test, not a result.

## Interpretation

The measure earns nothing on a two-cell policy. Two cells get covered in practice, so
running decision-class coverage on a Gatekeeper constraint mostly confirms what is already
true. It earns its keep as the decision structure grows: TrustWeave's policy decides over
trust level x action class, where the cells a suite must witness grow with the product
rather than with the line count, and where the orthogonality witness shows structural
coverage going to 100% while the suite stays blind. This corpus contains almost nothing in
that regime, which bounds what these numbers can be used to claim.

The honest summary is that decision-class coverage is cheap, exact, and mostly redundant on
today's published policy -- and that the four verified blind subjects it did surface, in
official upstream libraries, were not caught by the structural coverage those projects
already run.

## Threats to validity

- These are curated upstream libraries, which are plausibly better tested than private
  policy. The direction of that bias is toward under-reporting blindness.
- Blindness is a property of a suite as written. It is not proof of a defect in the policy,
  only that the suite could not detect one class of defect.
- Kyverno subjects that name no rule are attributed to `policy/*`, which merges rules of a
  multi-rule policy. 5 subjects could not have their type resolved at all.
- The Cedar corpus is 24 files and 78 requests. Its percentages carry wide error bars.
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
