# Protocol: the exact adequacy of real Rego suites

This protocol was written before the study it describes was run on the population below, and
`scripts/rego_exact_study.py` refuses to run on that population unless this file hashes to the
value fixed in the script. Like the three protocols before it (`EXACT_EVALUATION_PROTOCOL.md`,
`EXACT_EVALUATION_PROTOCOL_CEDAR.md`, `SUITE_ADEQUACY_PROTOCOL_REGO.md`), it is a hash recorded by
the authors in the same working session, not an externally timestamped registration; the commit
that adds it precedes the commit that adds the study's results.

## The question

The suite study (`SUITE_ADEQUACY_PROTOCOL_REGO.md`, `docs/rego-suite-adequacy-v1.json`) found that
the author-written suites of the OPA Gatekeeper library reach 93.8% line coverage on average yet
kill 70.6% of their modules' mutants. That kill rate counts every mutant, including those no test
could kill because they are equivalent to the module, so it is a lower bound on what the suites
pin down, not a measurement of it. Inside the fragment, equivalence is decidable. This study
decides it, for the suite study's own mutants, on the modules the membership measurement judged
inside, and reports for each suite:

- how many of its surviving mutants are **equivalent** to the module (no input separates them);
- its **exact mutation score**: the mutants it kills through the decision, over the mutants some
  input separates from the module;
- for every surviving mutant that is not equivalent, **an input that kills it**.

## The population

- **Corpus, engine, mutants:** exactly those of the suite study -- `gatekeeper-library` at commit
  `e034212e94e666ab3ba69108d96222bffc8ef671`, OPA 1.20.2 with `--v0-compatible`, the shared
  libraries `src/rego/lib_*`, and the mutants `scripts/rego_source_mutation.py` generates from each
  module's source, in its order.
- **Modules:** the suite study's measured modules (49) whose verdict in
  `docs/fragment-membership-rego-wide-v1.json` is *inside*: 18 modules. The other 31 are outside
  and are not studied: 25 are policy schemas, whose guards are stated against parameters a
  Constraint supplies, and 6 read `data.inventory`, a document the host injects.
- **Development set:** `src/general/httpsonly/src.rego`, the suite study's development module, is
  the only module the harness was run on while it was written and debugged. It is reported,
  flagged, and not pooled into any headline figure. The other 17 modules' sources were read, not
  run, while this protocol was written, to fix which constructs the witness space must cover.

## What a policy is here

A Gatekeeper module decides on an input `{"review": r, "parameters": p}`; no other key of `input`
is ever present. The **decision** is the suite study's: the input is denied when the module's
`violation` set is non-empty and allowed when it is empty. An input on which evaluation fails is
decided `error`, an outcome like allow and deny. A Constraint fixes `p`; the review varies. Each
module's **instantiations** are the distinct values of `input.parameters` -- absent counted as one
value -- under which its own suite evaluates it, recorded by running the suite once on the
unmutated module with a copy that prints `input` at the start of every `violation` rule body. A
mutant is **equivalent under p** if no review separates it from the module when the parameters
are `p`; it is **suite-equivalent** if it is equivalent under every instantiation of its suite,
and **distinguishable** otherwise. Through its decision, a suite can only kill a distinguishable
mutant.

## The witness space

Per module and instantiation, the review's observables are the paths the module and its mutants
read below `input.review`, found by resolving every reference through the variables, rules and
functions that bind it: an element of an iterated collection is a path with a wildcard, a
function parameter carries the paths its call sites pass, `object.get` with a constant key is a
path, and a read of `input.parameters` is the constant `p` gives it. A path read only to build a
message is still an observable, because a message that reads an absent field makes the rule
undefined. Each observable's candidates are:

- every constant it is compared with, in the module or in any of its mutants (so the string
  `"tw-mutant"` and the number `n + 1` that the literal operators substitute are candidates);
- for a string constant `c`: a fresh string, `"tw-mutant"`, one value that is not a string, and
  the strings an operator distinguishes -- `c` extended at its end for `startswith`, at its start
  for `endswith`, on both sides for `contains`, `c` with its case changed for `lower` and `upper`;
- for a pattern of `regex.match` or `glob.match`: one string per alternative the pattern names,
  generated from its syntax, and the fresh string, which it does not name;
- for a number `t` compared or tested for equality: `t - 1`, `t`, `t + 1` and `t + 2`;
- for a constant related to a field only through a function the construction does not model (a
  path split on `/`, say): `c`, `c/`, `c/tw`, `ctw` and `c` without its last character;
- for a value used as a condition: `true`, `false` and a non-boolean value;
- for a field whose type is tested: one value of each JSON type;
- for a field whose size is compared with `n`: collections of sizes `n - 1` to `n + 2` (from zero);
- **absent**, because a review may omit any field.

A **cell** is one choice per observable. An iterated collection is an array, or a map when the
authors' inputs show a map there; it is absent, empty, or holds one element whose fields are one
choice each. It also holds two elements -- each element value beside a default element -- when its
size is compared with a number or when the module compares any two observables with each other,
and `n - 1` to `n + 2` copies of the default element when its size is compared with `n`.
Collections that no expression relates are populated one at a time, the rest absent; collections
related by an expression are populated together. A module whose cells for one instantiation would
exceed **250,000** is excluded and counted by name (one engine pass over the development module's
43,726 cells takes two seconds).

Every decision -- of the module and of each mutant, on every cell -- is the engine's: one OPA
process per module and per mutant evaluates it on every cell, and on every input the checks below
draw, with `with input as`. No model of Rego written for this study decides anything. A mutant the
engine does not compile is **stillborn**: the suite study counted it as killed, because its suite
does not pass with it, and here it is reported as its own bucket and excluded from the exact score.

## Completeness, checked three ways

A witness space is exact only if no input separates a mutant from its module that no cell
separates. For every module and instantiation:

1. **Drawn reviews:** 200 reviews drawn by perturbing cells -- an element duplicated or another
   added to a collection, a value replaced by one of another type or by another cell's value, an
   unrelated field added, a field or a parent object removed.
2. **The authors' own reviews:** every review the suite evaluates the module on, as recorded
   above, and 200 more drawn by perturbing them in the same ways. These do not come from the
   witness space's construction, so they check it independently.
3. **The suite's own kills:** a mutant the suite kills whose decision differs from the module's on
   one of the authors' reviews is distinguishable by an input the authors wrote; check 2 evaluates
   every mutant on those reviews.

A mutant that differs from its module on any of these inputs and on no cell is a **missing
cell**: the module fails, is excluded, and is reported by name with the input. This is a
pass/fail criterion, not a rate. Seeds are fixed per module (`20261004:<module>`).

## Kills

A mutant is **killed** when the module's suite no longer passes with the mutant in the module's
place, run exactly as the suite study runs it. The kill counts must reproduce the suite study's per
module; a module where they do not is reported, not silently re-measured. A kill of a
suite-equivalent mutant is a kill **without a change in the decision** -- through the number or the
content of the violations (the suites assert `count(violation) == n`) or through a test that calls
a helper rule directly -- and is reported as its own bucket, never as a kill of a distinguishable
mutant.

## Measures

Per module, pooled over the 17 modules that pass, and with the development module reported
separately:

- mutants, stillborn (and how many of the suite study's kills they are), suite-equivalent,
  distinguishable, killed, killed through the decision (distinguishable and killed), killed without
  a change in the decision (suite-equivalent and killed);
- the **raw score** of the suite study, killed over mutants, recomputed here;
- the **exact score**, distinguishable and killed over distinguishable;
- the suite study's **survivors** split into the equivalent, the stillborn, and the **real** ones
  (distinguishable and not killed), each real one with one killing input -- the first cell, in
  construction order, on which its decision differs from the module's -- and the module's own
  decision there.

The **headline** is the share of the suite study's survivors that are equivalent, and the exact
score against the raw score, pooled and as a mean over modules, with a 95% bootstrap interval for
the mean difference (10,000 resamples of modules, seed 20261004). Nothing here is a hypothesis
test: every number is exact, and the interval describes the spread over modules.

**Closing the gaps:** each module's killing inputs are added to its suite as new tests, each
asserting the module's own decision there, and the extended suite is run on every mutant as the
shipped one was. It must kill every distinguishable mutant, and the suite-equivalent mutants it
kills must be exactly those the shipped suite killed; any exception is reported.
