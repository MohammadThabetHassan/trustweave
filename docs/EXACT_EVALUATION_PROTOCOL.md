# Protocol: two studies that use exact equivalence as ground truth

This protocol was written before either study was run. `scripts/exact_evaluation_study.py`
records this file's SHA-256 in every artifact it writes and refuses to run if the file has
changed since that hash was fixed in the script. That is a hash recorded by the same
authors in the same working session, **not** an externally timestamped registration, and
any deviation from what follows is listed in the artifact's `deviations` field and in the
paper.

Both studies rest on one property of the fragment: inside it, whether a mutant is
equivalent to its policy is decided, not estimated. So "how many faults does this suite
detect" and "is this edit a real change" have exact answers. That makes it possible to score
suite strategies and review tools against ground truth instead of against a lower bound.

## The policies

- **Reference policy:** `policies/default-policy.json`, the policy of the paper's worked
  example. It is reported separately and is not pooled with the generated policies.
- **Generated policies:** drawn by `interpreter_oracle.generate_policy` from
  `random.Random(20261003)`, one generator for the whole draw. A candidate is kept when the
  parser accepts it and its product witness space, pooled over the reference and every
  mutant of both operator sets, has at most **5,000** cells. Candidates are drawn until
  **300** are kept. Rejected and over-cap candidates are counted, not hidden.
- Every kept document is written to `docs/generated-policy-sample-v1.json`, so both studies
  can be re-run on the same policies without replaying the generator.

## The faults

Two operator sets. Both are reported, separately.

- **Set A (the paper's operators):** exactly `policy_mutation._mutants` -- `delete_rule`,
  `flip_decision`, `widen_trust`, `widen_action`, `narrow_trust`, `narrow_action`,
  `default_decision`, `swap_rules`. Set A is the primary fault model.
- **Set B (extended):** Set A plus, for every rule and every optional predicate the rule
  states (`source_data_classifications`, `source_data_classification_at_least`,
  `source_data_classification_at_most`, `tool_capabilities`, `source_identifiers`,
  `tool_identifiers`, `purpose_tags`):
  - `drop_<field>`: remove the predicate;
  - `narrow_<field>[v]`: for a list with more than one value, remove value `v`;
  - `widen_<field>[v]`: add a value `v` that the policy names for the same field in another
    rule (for classifications, any level of the declared taxonomy) and this rule lacks;
  - `shift_<bound>[v]`: move a classification bound to each other level of the taxonomy.
  No operator introduces a literal the policy does not already name, so the pooled witness
  space is the policy's own.
- A mutant whose decision map cannot be computed is **unrunnable**: it is counted and
  excluded from every denominator. It is never counted as equivalent.
- A mutant is **equivalent** when its decision map over the pooled product space equals the
  policy's (Theorem 2), and **live** otherwise.

## Study 1: which suite strategy detects the most faults

Let `N` be the number of cells of the pooled product space (the common refinement of the
policy's partition and every mutant's), `Delta(M)` the cells where mutant `M` decides
differently from the policy, `C` range over the classes of the policy's own quotient
`~P` (cells grouped by the truth value of every guard of the policy), and `D_d` the cells
the policy decides as `d`.

Strategies, each a suite consistent with the policy:

| Strategy | Suite | Size |
|---|---|---|
| `refinement` | one witness per cell of the pooled product space | `N` |
| `quotient` | one witness per class of `~P`, chosen uniformly among the class's cells | `|~P|` |
| `decision` | one witness per decision in the policy's range, chosen uniformly among `D_d` | `|range|` |
| `random_quotient` | `|~P|` cells drawn uniformly without replacement | `|~P|` |
| `random_decision` | `|range|` cells drawn uniformly without replacement | `|range|` |

The random strategies draw from the pooled product space. That frame belongs to a tester
who knows every literal the policy and its mutants name, which is a **favourable** random
baseline, and the paper says so.

No strategy is sampled. Each mutant's detection probability is exact:

- `refinement`: 1 if `Delta(M)` is non-empty (Corollary 4); it must equal 1 for every live
  mutant, and the script fails if it does not.
- `quotient`: `1 - prod_C (1 - |Delta(M) & C| / |C|)`.
- `decision`: `1 - prod_d (1 - |Delta(M) & D_d| / |D_d|)`.
- `random_*` of size `s`: `1 - C(N - |Delta(M)|, s) / C(N, s)`.

A policy's **expected mutation score** under a strategy is the mean detection probability
over its live mutants, computed in exact rational arithmetic and rounded only when written.
Policies with no live mutant have no score and are counted separately.

**Hypotheses** (generated policies, Set A primary, Set B secondary):

- **H1** (structure, at equal size): `quotient` > `random_quotient`.
- **H2** (the paper's criterion against the proxy): `quotient` > `decision`.
- **H3** (the proxy, at equal size; two-sided, no prediction): `decision` vs
  `random_decision`.

## Study 2: which policy changes each reviewer flags

Each live or equivalent mutant is treated as a proposed change to its policy. Ground truth,
exact over the pooled product space:

- **semantic change:** the mutant is live;
- **weakening:** some cell decides more permissively under the mutant, in the order
  `deny` < `require_approval` < `allow`.

Reviewers:

- **TrustWeave's diff signals:** `diff._policy_changes` on the two policy documents, fed to
  `policy_weakening.policy_review_signals`. It *flags a change* when it emits any signal,
  and *flags a weakening* when it emits one of `TW-DIFF-004`, `-005`, `-006`, `-007`,
  `-008` or `-009` (the signals its own docstring classifies as weakenings).
- **Text diff:** flags every change.
- **A suite run** (the `decision` and `quotient` strategies of Study 1): flags a change when
  a test fails; flags a weakening when a failing test's actual decision is more permissive
  than its expected one. Detection probabilities are exact, as in Study 1.
- **Exact table comparison** (Theorem 2): flags exactly the semantic changes and exactly the
  weakenings, by construction; it is reported as the reference, with its cost stated as the
  number of cells it decides per change.

For each reviewer and each target (semantic change, weakening): precision and recall,
pooled over all changes, plus recall broken down by operator. Human review time is not
measured; that needs people.

## Analysis

- Paired, per policy. For each hypothesis, the mean and median paired difference, a 95%
  percentile bootstrap interval over policies (10,000 resamples, seed 20261003), and a
  sign-flip permutation test on the mean difference (10,000 permutations, seed 20261003;
  one-sided for H1 and H2, two-sided for H3), with Holm's correction across the three.
- Effect: the number of policies on which each strategy wins, ties and loses.
- Strata, descriptive only: by the size of the policy's decision range (1, 2 or 3).
- Every figure the paper quotes is read from the artifacts by `scripts/check_manuscript.py`.
