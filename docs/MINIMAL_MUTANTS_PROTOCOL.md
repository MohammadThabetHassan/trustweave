# Protocol: the payoff over subsumption-minimal mutants

This protocol was written before the study it describes ran on any policy, and
`scripts/minimal_mutant_study.py` refuses to run unless this file hashes to the value fixed in the
script. Like the paper's other protocols, it is a hash the authors recorded in the same working
session, not an externally timestamped registration.

## Why

The payoff studies score suites over every live mutant. A redundant mutant, one killed whenever
another is, can inflate a score and the gap between two strategies (Papadakis et al. 2016).
Minimal mutant sets remove them (Ammann, Delamaro and Offutt 2014; Kurtz et al. 2014). Outside a
decidable fragment they are estimated over a pool of tests. Inside it, every mutant is constant
on each witness cell, so a mutant's difference set over the cells is exact. Subsumption is then
inclusion between difference sets, and the minimal set is computed exactly.

## Definition

A live mutant is minimal when no other live mutant's difference set is a strict subset of its
own. Live mutants with identical difference sets count once. Equivalent mutants, whose difference
set is empty, are already excluded.

## Population

- The 300 generated policies of `docs/generated-policy-sample-v1.json`, under operator set A.
- The 96 Cedar files of the primary analysis of `docs/cedar-suite-strategy-study-v1.json`.

These are the populations of `docs/combination-criteria-study-v1.json`. Two others are out:

- **Rego:** the payoff study did not record per-mutant difference sets, and recomputing them
  takes engine-hours.
- **The real faults:** they are not mutants.

## Strategies

- **The payoff studies' four:** one witness per quotient class, a random suite of the quotient's
  size, the decision proxy (one witness per decision the policy makes), and a random suite of the
  proxy's size.
- **The criteria study's:** each choice, base choice, pairwise and three-wise coverage (100 seeded
  constructions each, with the same seeds), and on the generated policies rule coverage, decision
  coverage and MC/DC.

Every suite is the one those studies built; only the set of mutants it is scored against changes.

## Measures

- **Detection:** expected detection, computed as the payoff studies compute it, averaged over a
  policy's minimal mutants instead of all its live ones; then the mean over policies.
- **Certain detection:** the share of minimal mutants detected whichever witness each quotient
  class contributes.
- **Redundancy:** per population, the live and the minimal mutants, and the distribution of
  minimal-set sizes over policies. A policy whose minimal set is one or two mutants stays in the
  paired comparisons.

## The reproduction gate

Over all live mutants, the instrument must first reproduce, at the published precision:

- `suite-strategy-study-v1`: operator set A's mean expected scores for the quotient, its random
  comparator, the proxy and its random comparator;
- the primary analysis of `cedar-suite-strategy-study-v1`: the same four;
- `combination-criteria-study-v1`: every strategy's mean score, random score and mean size.

A population that does not reproduce is reported and not scored.

## Hypotheses

Over minimal mutants, for each population and one-sided:

- **H1m:** the quotient detects more than a random suite of its size;
- **H2m:** the quotient detects more than the decision proxy;
- **Q_s^m:** for each criterion s, the quotient detects more than s.

The test is on the paired per-policy differences, with:

- a 10,000-resample bootstrap 95% interval;
- the sign-flip p value, computed as the earlier studies compute it;
- Holm's correction within each population, over its hypotheses;
- seed 20261004.

Only the directions are fixed here, not magnitudes.

## What the paper says in each outcome

- **If H1m and H2m hold:** the payoff survives the removal of redundant mutants. The paper reports
  the scores over minimal mutants beside those over all mutants, both halves, like for like.
- **If either fails, or a mean difference changes sign:** the paper says so where it states the
  all-mutant result, and withdraws any statement it contradicts.
- **Each Q_s^m:** reported per criterion in the same way.

## Deviations

Any departure from this protocol is recorded in the artifact, with its reason.
