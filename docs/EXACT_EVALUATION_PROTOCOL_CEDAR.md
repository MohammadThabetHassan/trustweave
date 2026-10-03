# Protocol: the suite-strategy study replicated on real Cedar policies

This protocol was written before the study it describes was run on the data below, and
`scripts/cedar_exact_study.py` refuses to run unless this file hashes to the value fixed in
the script. It is a hash recorded by the authors in the same working session, not an
externally timestamped registration. The first protocol,
[`EXACT_EVALUATION_PROTOCOL.md`](EXACT_EVALUATION_PROTOCOL.md), is unchanged; this one adds a
population, it does not amend that one.

The first study ran on generated policies in the authors' own language. This one asks the
same three questions of policy other people wrote, in a language with an engine the harness
can call: Cedar, through the `cedarpy` bindings (Cedar 4.12.1), which decides every request
below. It is the language of the study whose policies are simplest, and it is the one chosen
because an engine is callable and a complete witness space is constructible for it; a
replication on Kyverno or Rego would need a cell enumerator for each, which does not exist.

## The policies

- **Population:** the files of `docs/third-party-sample-cedar-corpus-v1.json` that the
  membership measurement judged inside and Cedar 4.12.1 parses, restricted to those whose
  every policy is **exact-eligible**: each scope constraint is `All`, `==`, `in` or `is` with
  named entities, and each condition is a boolean combination (`&&`, `||`, `!`) of atoms that
  compare one request term with literals -- `==`/`!=` against a literal, `<`/`<=`/`>`/`>=`
  against an integer literal, `has`, `in` a named entity or set of named entities, `is` a
  named type, `contains`/`containsAll`/`containsAny` with literal arguments, or a boolean
  attribute used directly. A request term is `principal`, `action`, `resource`, `context`,
  or an attribute chain off one of them. Files using anything else are counted by reason and
  excluded; templates are schemas and were excluded already.
- **Primary analysis:** eligible files with at least one condition. **Secondary:** every
  eligible file. Scope-only files have quotients of a few cells that every strategy covers,
  so they are reported, not pooled into the primary test.
- **Development set:** the vendor Cedar files of `docs/fragment-membership-cedar-wide-v1.json`
  were the only data used while the script was written and debugged, and they are not part of
  any result.

## The witness space

Per file, the observables are: the principal's, action's and resource's identity and type,
their named ancestors, and every attribute chain the policies read. Each observable's
candidates are the literals it is compared with, a fresh value of each literal type,
`t - 1`, `t` and `t + 1` for every integer threshold `t`, every subset of the literals a
set-valued chain is tested against, `true` and `false` for a chain used as a boolean, and
**absent**, because a request may omit an attribute and Cedar then skips the policy with an
error. Identities include every named entity of the right role, a fresh entity of each named
type, and a fresh entity of a fresh type; ancestors range over every subset of the named
entities the policies test with `in`. A cell is one choice per observable. Files whose
product exceeds **20,000** cells are excluded and counted.

The quotient classes of a file are its cells grouped by the value -- true, false or error --
that the engine gives each atom of the file's policies, every atom evaluated as its own
one-line policy. No class is computed by a model of Cedar written for this study.

## Completeness, checked adversarially

A witness space is only exact if no request distinguishes a mutant from its policy that no
cell distinguishes. For every file the script draws **200** requests from the candidates
perturbed -- fresh strings and integers, thresholds `+-2`, subsets with fresh members,
attributes added and removed, fresh ancestors and types -- and evaluates the policy and every
mutant on each. A mutant that differs from its policy on a drawn request and on no cell is a
**missing cell**: the file fails, is excluded, and is reported by name. This is a pass/fail
criterion, not a rate.

## The faults

Mutation operators on the policy set, applied through Cedar's JSON form and converted back
to policy text: flip a policy's effect; delete a policy; drop a condition; turn `when` into
`unless` and back; widen a scope constraint to `All`; replace a conjunction or disjunction by
either side; swap `==` and `!=`; move a strict ordering to the non-strict one and back; and
replace a compared literal by another literal the file compares the same term with. A mutant
the engine cannot parse is unrunnable, counted, and excluded. Equivalence is equality of
decision maps over the cells.

## Strategies, scores and hypotheses

Identical to the first protocol: `refinement`, `quotient`, `decision`, `random_quotient` and
`random_decision`, every detection probability in closed form, every expected score exact.
The decision domain is Cedar's `Allow` and `Deny`, so the decision suite always has two
cases, and H3 compares two cases with two random cells -- a narrow comparison, reported as
such. **H1**: `quotient` > `random_quotient`. **H2**: `quotient` > `decision`. **H3**
(two-sided): `decision` vs `random_decision`. Analysis as in the first protocol: paired per
file, bootstrap intervals and sign-flip permutation tests with 10,000 resamples at seed
20261003, Holm's correction, wins, ties and losses.

## Real edits, descriptive only

The sampled files' histories are shallow -- 61 earlier-version pairs among the eligible files
-- too few to test anything. Each pair whose both versions are eligible is reported as a real
edit: whether it changes a decision, whether it weakens one, and each strategy's detection
probability for it. No hypothesis is tested on them.
