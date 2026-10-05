# Protocol: the exact adequacy of real Kyverno suites

This protocol was written before the study it describes was run on the population below, and
`scripts/kyverno_exact_study.py` refuses to run on that population unless this file hashes to the
value fixed in the script. Like the protocols before it, it is a hash recorded by the authors in
the same working session, not an externally timestamped registration; the commit that adds it
precedes the commit that adds the study's results.

## The question

The Rego study (`EXACT_ADEQUACY_PROTOCOL_REGO.md`) decided which surviving mutants of the
Gatekeeper library's suites are equivalent to their modules, and found the suites more adequate
than their raw kill rate says. This study asks the same question of a second admission language
and a second library: the Kyverno policy library, whose policies ship author-written suites run by
`kyverno test`. For each suite it reports:

- how many of its surviving mutants are **equivalent** to the policy (no admission request
  separates them);
- its **exact mutation score**: the mutants it kills, over the mutants some request separates from
  the policy;
- for every surviving mutant that is not equivalent, **a resource that kills it**.

Kyverno policies take no parameters, so unlike the Rego study the equivalences here are not
relative to a parameter setting. The admission operation is part of the request and is treated as
one more observable where a policy reads it.

## The population

- **Corpus, engine, mutants:** the Kyverno library `kyverno/policies` at commit
  `ef9843f08d25b3555fe69616f8612c9f915af5d4`, the corpus of
  `docs/fragment-membership-kyverno-wide-v1.json`; the Kyverno CLI 1.19.1; and the mutants
  `scripts/kyverno_mutation.py` generates from each policy file (`_mutate`), in its order and
  without its experiment's cap of eight mutants or floor of three.
- **Policies:** those `scripts/fragment_membership_kyverno.py` discovers in that corpus (each
  policy keyed by the name its test manifest states, the base file of each name) whose verdict in
  the membership artifact is *inside*, and that meet every condition below. The instrument
  computes the population and records the reason for every exclusion by name.
  1. The policy's test manifest names exactly one policy file, which holds one document, of kind
     `ClusterPolicy`.
  2. Every rule is a `validate` rule whose guard is a `pattern`, an `anyPattern` or
     `deny.conditions`, optionally with `preconditions`; no rule uses `context`, `foreach`, `cel`,
     `podSecurity`, `manifests` or `assert`.
  3. Every condition key, in preconditions and in deny conditions, is `request.operation` or a
     path below `request.object` written as names and quoted names, either optionally followed by
     `|| '<literal>'`; every condition value is a literal or a list of literals. No pattern value
     contains a variable.
  4. Every `match` and `exclude` block selects by `resources` alone, using only `kinds`, `names`,
     `namespaces` and `operations`.
  5. The policy's suite passes with the unmodified policy, and the policy has at least one mutant.

  Static inspection of the policy texts while this protocol was written found 127 of the 206
  inside policies meeting conditions 1 and 2, and 86 meeting conditions 1 to 4; condition 5 needs
  the engine, and the instrument's count is the one reported.
- **Development set:** `require-labels`, `disallow-privileged-containers` and `restrict-nodeport`
  are the only policies the instrument was run on while it was written and debugged. They are reported, flagged, and not pooled into any headline figure. Other policies'
  texts were read, not run, to fix which constructs the witness space must cover.

## What a policy is here

Kyverno decides an admission request rule by rule. For a resource and an operation, a policy's
**decision** is the map from each rule the engine evaluates, including the rules it generates for
pod controllers, to its result: `pass`, `fail`, `skip`, `warn` or `error`, or no result when the
rule does not apply to the resource. A mutant is **equivalent** if no resource and operation give
it a different decision from the policy's, and **distinguishable** otherwise. A mutant the engine
cannot load, or with which the suite produces no test summary, is **stillborn**; it is reported
as its own bucket and excluded from both scores, as the mutation experiment excludes it.

## The witness space

Per rule, the request's observables are:

- every leaf of the rule's `pattern` and of each `anyPattern` alternative, identified by its path
  from the resource root with anchors removed and `[]` marking a list element;
- the presence of every key that carries an anchor (`=(k)`, `X(k)`, `(k)`, `^(k)`, `<(k)`);
- every `request.object` path a condition reads, with the condition's values;
- the operation, where a condition reads `request.operation`.

Each observable's candidates are:

- for a pattern value written as a string: the alternatives it separates with `|` or `&`, each
  with a leading `!` removed. For a comparison (`>`, `>=`, `<`, `<=`) or a range against a number,
  quantity or duration `n`: `n - 1`, `n` and `n + 1` in the same unit. For an alternative with `*`
  or `?`: the alternative with `*` replaced by nothing and `?` by `a`, with `*` replaced by `tw`,
  and the first of these with its last literal character changed. Otherwise the alternative itself
  and the alternative with `x` appended;
- for a number `n`: `n - 1`, `n` and `n + 1`; for a boolean or the strings `true` and `false`:
  `true` and `false`;
- for a condition: every literal its value names, each with `x` appended, and `n - 1` and `n + 1`
  for a number;
- for the operation: `CREATE`, `UPDATE`, `DELETE`, `CONNECT`, and unset;
- for every observable: the empty string, the fresh string `tw-fresh`, and **absent**.

Candidates are drawn from the policy and from every one of its mutants, so a threshold or operator
a mutant introduces has its witnesses. A list in a pattern is absent, empty, or holds one element
whose fields are one choice each. A **cell** is one choice per observable of one rule; the other
rules' observables are absent. The cells of a rule are the product of its observables' candidates,
and each cell is one resource: of the first kind the rule's `match` names, with the API version and
namespacing of the suite's own resources of that kind (or of the core Kubernetes kind when the
suite has none; a policy whose kind has neither is excluded by name), named `tw-<rule>-<cell>`, in
namespace `default` when namespaced. Cells that read
the operation are decided once per candidate operation. A policy whose cells would exceed
**20,000** over all its rules and operations is excluded and counted by name.

Every decision, of the policy and of each mutant on every cell, is the engine's:
`kyverno apply` with `--policy-report`, one process per policy or mutant and per operation, over
all of its cells at once. No model of Kyverno written for this study decides anything.

## Completeness, checked three ways

A witness space is exact only if no request separates a mutant from its policy that no cell
separates. For every policy:

1. **Drawn resources:** 200 resources drawn by perturbing cells: a list given a second element taken
   from another cell, a value replaced by another cell's value or by a value of another type, an
   unrelated field added, a field or its parent removed. Each is decided under every operation the
   policy reads, or under the default when it reads none.
2. **The authors' own resources:** every resource in the files the suite's manifest lists, and 200
   more drawn by perturbing them in the same ways. These do not come from the witness space's
   construction, so they check it independently.
3. **The suite's own kills:** every mutant, killed or not, is decided on the authors' resources, so
   a mutant the suite kills is distinguishable by an input the authors wrote.

A mutant that differs from its policy on any of these inputs and on no cell is a **missing cell**:
the policy fails, is excluded, and is reported by name with the input. This is a pass or fail
criterion, not a rate. Seeds are fixed per policy (`20261004:<policy>`).

## Kills

A mutant is **killed** when the policy's suite no longer passes with the mutant in the policy's
place, run as `scripts/kyverno_mutation.py` runs it: the policy's directory is staged, the mutant
written over the policy file, and `kyverno test` run on the suite. A suite that produces no test
summary is a run that failed, not a kill, and makes the mutant stillborn. A kill of an equivalent
mutant would mean the suite observes something other than the decision; it is reported as its own
bucket.

## Measures

Per policy, pooled over the policies that pass, and with the development set reported separately:

- mutants, stillborn, equivalent, distinguishable, killed, and killed but equivalent;
- the **raw score**, killed over the mutants that are not stillborn;
- the **exact score**, distinguishable and killed over distinguishable;
- the survivors split into the equivalent and the **real** ones (distinguishable and not killed),
  each real one with one killing resource, the first cell in construction order on which its
  decision differs from the policy's, and the policy's own result there;
- the mutants by operator family (operator, threshold, weakening, anchor, boolean), descriptively.

The **headline** is the share of survivors that are equivalent, and the exact score against the
raw score, pooled and as a mean over policies, with a 95% bootstrap interval for the mean
difference (10,000 resamples of policies, seed 20261004). Nothing here is a hypothesis test: every
number is exact, and the interval describes the spread over policies.

**Closing the gaps:** each policy's killing resources are added to its suite as new tests, each
asserting the policy's own result for the rule the mutant changes, and the extended suite is run on
every mutant as the shipped one was. It must kill every distinguishable mutant and no equivalent
one; any exception is reported.

## What the paper says, decided now

- The share of survivors that are equivalent, the exact and raw scores and the number of real gaps
  are stated whatever they are, beside the Rego study's.
- If few survivors are equivalent, the paper says that the raw score understates little on Kyverno,
  and that the Rego result does not generalise in size.
- The policies that fail the completeness check, exceed the cap, or fall outside the conditions
  above are counted by reason, and the results are said to cover only the policies that pass.

The artifact is `docs/kyverno-exact-adequacy-v1.json`; the instrument is
`scripts/kyverno_exact_study.py`, and the witness construction `scripts/kyverno_witness_space.py`.
