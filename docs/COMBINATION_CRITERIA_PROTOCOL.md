# Protocol: established selection criteria and the quotient, at matched size

This protocol was written before the study it describes computed any outcome, and
`scripts/combination_criteria_study.py` refuses to run on the populations below unless this file
hashes to the value fixed in the script. Like the paper's other protocols, it is a hash the
authors recorded in the same working session, not an externally timestamped registration; the
commit that adds it precedes the commit that adds the study's results.

## Why

One witness per class of the policy-relative quotient is all-combinations coverage over the
policy's guard atoms (Ostrand and Balcer's category partition; Grindal, Offutt and Andler's survey
of combination strategies, STVR 15(3), 2005). The paper compares it with random suites and with a
decision proxy of its own. A referee asked how it compares, at matched size, with established
criteria. On XACML that comparison exists, with Xu et al.'s own generators
(`docs/xacml-criteria-study-v1.json`). This study makes it on the generated and Cedar populations
of the paper's payoff section, scoring the cheaper combination strategies there, and the
rule-structure criteria where the rule structure is explicit, exactly as the earlier studies
scored the quotient.

## Populations

1. **Generated.** The 300 policies of `docs/generated-policy-sample-v1.json`, under the paper's
   operator set (set A), with the witness space and decision map of
   `scripts/exact_evaluation_study.py`, unchanged.
2. **Cedar.** The 96 files of the primary analysis of `docs/cedar-suite-strategy-study-v1.json`
   (status `scored`, at least one condition, at least one live mutant), with the witness space,
   atoms, mutants and decisions of `scripts/cedar_exact_study.py`, every decision the Cedar
   engine's (cedar-policy 4.12.0 through cedarpy 4.12.1), unchanged. The completeness check is
   not repeated: every one of the 96 passed it in that study.

**Not included.** Rego: its classes key a nested structure, in which a collection is the set of
its elements' signatures, not a vector of atom values, so t-way coverage there would need a
flattening rule this protocol does not fix. XACML: already scored with Xu et al.'s own tool.

**Development.** The instrument is built and tested on the reference policy
(`policies/default-policy.json`) and on synthetic policies in its tests; no policy of either
population is used before the run. The reference policy's results are reported apart.

## Factors

A class of the quotient is a vector of atom values: for the generated population one Boolean per
rule and predicate dimension (`policy_mutation.predicate_signature`), for Cedar one value per atom
(`Allow`, `Deny` or `error`, as `cedar_exact_study._signatures` gives them). A position taking one
value over all of a policy's classes is fixed, not a factor. Positions identical over all classes
are merged into one factor, the first kept. A factor's feasible values, and a combination's
feasibility, are those some class takes.

## Strategies

Every strategy builds a suite of groups of cells, and each group contributes one test: a cell
drawn uniformly from it.

**Combination strategies** (both populations); each group is a class:

- **All combinations:** every class, the quotient.
- **Each choice:** a greedy cover of every feasible value of every factor.
- **Pairwise:** a greedy cover of every feasible combination of values of two factors.
- **Three-wise:** the same for three factors.
- **Base choice:** the base is the largest class, ties broken by the seeded order. For each factor
  and each feasible value other than the base's, the suite adds the class with that value that is
  nearest the base in Hamming distance over factors, ties broken by the seeded order. The suite
  is the set of those classes and the base.

A greedy cover repeatedly adds the class covering the most uncovered requirements, ties broken by
a seeded uniform order, until every feasible requirement is covered. Each combination strategy is
constructed **100 times per policy**, with seeds derived from the study seed and the policy's
position, and score and size are averaged over the constructions.

**Rule-structure criteria** (generated population only, whose rules are explicit); each group is
the set of cells satisfying one requirement:

- **Rule coverage:** for each rule, the cells at which it decides (its guard holds and no earlier
  rule's does); for the default, the cells at which no guard holds.
- **Decision coverage:** for each rule, the cells at which it is reached (no earlier guard holds)
  and its guard holds, and the cells at which it is reached and its guard fails.
- **MC/DC:** for each rule, the cells at which it decides, and for each of its dimensions that is
  not fixed, the cells at which the rule is reached, that dimension fails and its other dimensions
  hold.

A requirement no cell satisfies is infeasible and dropped; the counts are reported.

## Detection

As in the earlier studies, and in rational arithmetic. A suite with one uniform test from each of
the groups G1, ..., Gk detects a mutant whose difference set is D with probability
1 - prod(1 - |D ∩ Gi| / |Gi|). A random suite of s cells drawn without replacement from N detects
it with probability 1 - C(N - |D|, s) / C(N, s). A policy's score under a strategy is the mean over
its live mutants. For a combination strategy it is averaged over the constructions, and each
construction's random comparator has that construction's size.

**Certain detection** (descriptive). The share of a policy's live mutants whose difference set
contains a whole class. Every suite with one witness per class detects these. The worst case over
joint choices of witnesses lies between this share and the expected score.

## Outcomes

**Primary, per population:**

- each strategy's mean score and mean size;
- the quotient's paired advantage over each strategy;
- each strategy's paired advantage over a random suite of its own size.

**Hypotheses.** All are one-sided and paired by policy. For each strategy s:

- **Q_s:** the quotient scores higher than s.
- **R_s:** s scores higher than a random suite of its size.

Each comes with a bootstrap 95% interval of the mean paired difference (10,000 resamples) and a
sign-flip permutation p-value (10,000 flips). The p-values are Holm-adjusted within a population.
The seed is 20261004.

**Secondary:**

- each strategy's size as a share of the quotient's;
- certain detection under the quotient;
- the reference policy, reported apart.

## Deviations

Any departure from this protocol is recorded in the artifact, with its reason.
