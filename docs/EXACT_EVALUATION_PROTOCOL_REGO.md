# Protocol: the suite-strategy study replicated on real Rego policies

This protocol was written before the study it describes was run on the population below, and
`scripts/rego_payoff_study.py` refuses to run on that population unless this file hashes to the
value fixed in the script. Like the protocols before it, it is a hash recorded by the authors in
the same working session, not an externally timestamped registration; the commit that adds it
precedes the commit that adds the study's results. The first two suite-strategy protocols
(`EXACT_EVALUATION_PROTOCOL.md`, `EXACT_EVALUATION_PROTOCOL_CEDAR.md`) are unchanged; this one
adds a population.

## Why

The first study ran on generated policies; the second replicated it on real Cedar policy and
said why only Cedar: it is the language whose policies are simplest, and "a replication on
Kyverno or Rego would need a cell enumerator for each, which does not exist". The exact-adequacy
study (`EXACT_ADEQUACY_PROTOCOL_REGO.md`) has since built one for Rego and checked it. This study
asks the three questions of the first two, on real Rego, with every decision taken by OPA.

## The policies

- **Population:** the modules of `docs/rego-exact-adequacy-v1.json` whose status is *measured*:
  Gatekeeper library modules inside the fragment whose witness spaces passed that study's
  completeness checks. A **policy** is a module under one instantiation -- one of the parameter
  values its own suite runs it under -- so a module contributes one policy per instantiation.
- **Development set:** `src/general/httpsonly/src.rego`, the development module of both Rego
  studies, is the only module the harness was run on while it was written. It is reported,
  flagged, and not pooled.

## Cells, decisions and mutants

The witness space is the exact-adequacy study's, built by the same code, so its completeness is
the one that study checked. The engine is OPA 1.20.2 with `--v0-compatible` and the library's
shared `lib_*` modules; every decision of the module and of each mutant, on every cell, is OPA's.
The mutants are the suite study's (`scripts/rego_source_mutation.py`); a mutant the engine does
not compile is excluded. A mutant is **live** under an instantiation when some cell separates it
from the module.

## The quotient

The module's atoms are the comparisons, calls and conditions of its source and of the library
functions it calls, recorded by the analysis that builds the witness space with each atom's
operator and the order of its operands, and its constants resolved under the instantiation. OPA
decides every atom at every value the cells give the path it reads. A cell's **signature** is,
for every path the module reads, whether the path is present and, where the module has atoms on
it, their outcomes; a collection's signature is the set of its elements' signatures. A path whose
atoms the analysis cannot restate as an expression -- an unmodelled builtin, or a comparison
between two paths -- is not merged: each of its values is a class of its own, which can only make
the quotient finer and its suite larger, and the artifact records how many such paths each policy
has. The **quotient classes** are the cells grouped by signature. They are the module's quotient
only if its decision is constant on every class, so that is checked: a policy where it is not is
excluded and counted.

## Strategies, scores and hypotheses

Identical to the first two protocols: `refinement` (one witness per cell), `quotient` (one per
class), `decision` (one per decision the module makes on the cells), `random_quotient` and
`random_decision` (that many cells drawn uniformly without replacement); every detection
probability in closed form, a policy's expected score the mean over its live mutants. **H1**:
`quotient` > `random_quotient`. **H2**: `quotient` > `decision`. **H3** (two-sided): `decision`
vs `random_decision`; the decision suite has two or three cases (deny, allow, and error where a
module errs), so H3 is a narrow comparison, as in the Cedar study. Analysis as before: paired
over policies, bootstrap 95% intervals and sign-flip permutation tests with 10,000 resamples at
seed 20261004, Holm's correction over the three, wins, ties and losses. Policies with no live
mutant are reported and not scored.

**A second reading**, reported beside the first with the same statistics but not as a
pre-registered test: the means over modules, each module's policies averaged, because the
policies of one module share its source.
