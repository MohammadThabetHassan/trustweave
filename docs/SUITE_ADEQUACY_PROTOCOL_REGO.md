# Protocol: what a real policy suite's coverage is worth

Fixed and hashed before the run. The script `scripts/rego_suite_study.py` records this file's
SHA-256 and refuses to run if the file has changed, so the figures cannot be read off a
protocol written to fit them. The companion studies on generated and on Cedar policy
(`EXACT_EVALUATION_PROTOCOL.md`, `EXACT_EVALUATION_PROTOCOL_CEDAR.md`) ask what the
equivalence-class criterion is worth against an exact oracle; this one asks the question a
reviewer asks first -- what the adequacy signal practitioners already read, the line coverage
`opa test --coverage` reports, is worth on the same kind of policy, measured against the faults
a mutation analysis seeds.

## Population

The OPA Gatekeeper library (`trustweave-corpora/rego/gatekeeper-library`, at its pinned commit)
is a corpus of Kubernetes admission policies written in Rego by their authors, each with an
author-written unit-test suite beside it (`<name>.rego` and `<name>_test.rego`, or
`src.rego`/`src_test.rego`, in one directory). The population is every such module that

- declares at least one `violation` decision rule, so that it has a decision whose change a
  mutation can alter -- the library's shared `lib_*` helpers have none and are excluded; and
- whose suite passes unchanged on the unmutated module under the engine used here (`opa test`,
  `--v0-compatible` for the corpus's v0 syntax). A suite that does not pass as shipped cannot
  be a yardstick, and the modules where it does not are excluded by name and counted.

The decision of a module is the non-emptiness of its `violation` set: an input is denied when
the set is inhabited and allowed when it is empty.

## Development set

`src/general/httpsonly` is the module the mutation operators and the harness were written and
debugged against. It is named here, reported with the rest, and flagged in the artifact, so the
headline figures can be read with it set aside.

## The mutation operators

`scripts/rego_source_mutation.py` edits the module's source at the locations
`opa parse --json-include locations` gives each rule, expression, operator and literal. One
edit per mutant:

- **delete a rule** -- remove a whole rule, dropping a path to a decision;
- **flip a comparison** -- `==`->`!=`, `!=`->`==`, `<`->`>=`, `<=`->`>`, `>`->`<=`, `>=`->`<`,
  the negation a suite that exercises only one side does not separate;
- **change a comparison's strictness** -- `<`<->`<=`, `>`<->`>=`, the boundary a suite without
  a boundary case does not separate;
- **drop a condition** -- replace a boolean condition with `true`, weakening a conjunction;
- **negate a condition** / **remove a negation** -- toggle a `not`;
- **change a literal** -- flip a boolean, add one to a number, replace a string.

This operator set is deliberately richer than, and distinct from, the one in
`scripts/rego_mutation.py` behind the decision-blindness association of the suite-coverage
study. That one searches the source text for a fixed list of operators (`==`->`!=`,
`true`->`false`, and the like); this one locates each span through the parser, which has two
consequences the comparison needs. It never edits an operator that happens to sit inside a
string literal -- a hazard that module's own code documents (67 of its mutants were edits to
`sprintf` format text) -- and it can add the structural and literal operators a text search
cannot apply safely: deleting a rule, dropping or negating a whole condition, and replacing a
literal. Those last are exactly the faults a suite is most likely to miss, so a coverage gap
measured without them would understate itself. Assignments (`:=`, `=`) are never dropped or
negated: removing one leaves a variable the rest of the rule reads unbound, which is a failure
to load rather than a change in behaviour. A mutant that no longer parses is stillborn and is
discarded, so every mutant scored is a module the engine loads.

## What is measured

For each module in the population:

- **Coverage** -- the percentage `opa test --coverage` reports for the module's own lines, run
  with its suite. This is the number a practitioner reads.
- **Mutation score** -- of the module's mutants, the fraction the unchanged suite kills. A
  mutant is killed when, loaded in place of the module with the same suite, the suite no longer
  passes: a test fails, or the mutant does not load in context (a conflict or an unsafe
  variable the whole program now has). A mutant the suite still passes is live.

The comparison is between the two, per module and in aggregate: the coverage a suite reports
against the fraction of seeded faults it actually detects. The gap is the quantity of interest
-- how much the adequacy signal in common use overstates what the suite pins down. Human review
time is not measured. As in the decision-blindness study, the live mutants are not here
classified as semantically equivalent or as real misses -- Gatekeeper policy is outside the
decidable fragment, so the mutation score is a lower bound on suite quality rather than an exact
figure, and separating the two needs the exact oracle of the companion studies.

## Analysis

Aggregates are reported as the mean and median over the population of the per-module coverage
and mutation score, and the per-module gap (coverage minus mutation score) with a percentile
bootstrap interval over modules (10,000 resamples, seed 20261003), paired because both numbers
come from the same module. The counts behind every figure are in the artifact
`docs/rego-suite-adequacy-v1.json`.
