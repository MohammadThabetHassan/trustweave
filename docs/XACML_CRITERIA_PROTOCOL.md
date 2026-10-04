# Protocol: Xu et al.'s coverage criteria and the quotient, on their own benchmark policies

This protocol was written before the study it describes computed any outcome, and
`scripts/xacml_criteria_study.py` refuses to run on the population below unless this file hashes
to the value fixed in the script. Like the paper's other protocols, it is a hash the authors
recorded in the same working session, not an externally timestamped registration; the commit
that adds it precedes the commit that adds the study's results.

## Why

The paper's threats section says that Xu, Shrestha and Shen's coverage criteria for XACML were
not compared with the quotient. This study compares them on their own terms: on the benchmark
policies of their tool, XPA; against XPA's own mutation operators; with the suites XPA's own
generators produce; and with every decision taken by Balana, the PDP XPA is built on.

## Materials

- **XPA**, the source at commit `89c000495d81a1a82ca8de2ab0fc73fecfc4e440` of
  `github.com/dianxiangxu/XPA`, built with JDK 17 against the Java 8 API and the libraries its
  `pom.xml` names, each from Maven Central with its published SHA-1 checked (commons-logging
  1.1.1, log4j 1.2.17, commons-io 2.5, opencsv 3.7, commons-lang3 3.4, poi 3.5-beta4, jdom
  1.1.3, diffutils 1.2), and the `mcdclib` 1.0 jar XPA keeps in its own repository. One class
  XPA references but does not contain at that commit, `org.seal.xacml.xpa.Experiment`, is
  supplied as a one-field stub; XPA reads it only to compose log messages.
- **Z3 4.6.0** (`z3-4.6.0-x64-win.zip`, SHA-256
  `d1dc7f6ae0a053ee490aa6899cdae52631d46d4f22993acd732d6835523c3ce1`), the release nearest the
  Z3 commit XPA pins as a submodule (`cfdde2f4`, 8 January 2018), called as XPA calls it: `z3
  smt.string_solver=z3str3 -smt2`.
- **Balana 1.2.24**, from Maven Central with Xerces 2.12.2 and xml-apis 1.4.01, decides every
  request in the study, through a harness that reads each request once and refuses to score a
  policy Balana's own reader rejects. XPA keeps an older, modified Balana for its own
  evaluation; the study does not use it.
- **The engine oracle.** Before any outcome, the harness decides Balana's own conformance cases
  at commit `47484171` of `wso2/balana`, the commit the paper's XACML corpus pins, and the
  agreement is recorded in the artifact. On every case Balana's own test suite runs it agreed
  during development.

## Population

The 20 policy files of XPA's `Experiments` directory at the pinned commit. A policy is eligible
when (1) the paper's membership procedure judges it inside the fragment; (2) it is
exact-eligible: every `Match` compares one attribute designator with one literal by an equality
or order function, and every condition combines, with `and`, `or` and `not`, comparisons of one
designator, directly or through a `one-and-only` function, with literals, or `is-in` and
`at-least-one-member-of` tests against a bag of literals, with no `AttributeSelector`; and (3)
its witness space has at most 20,000 cells, the cap of the paper's Cedar study. Eleven are
eligible; the table at the end gives every file's reason.

**Development.** No policy of the population was used to build the instrument. The harness, the
mutator and the generators were developed on a synthetic policy written for the purpose and on
Balana's conformance cases.

## The request universe

A request supplies each attribute a policy reads at most once, or not at all, plus one constant
attribute in a category no policy reads, because Balana rejects a request with no attributes as
malformed; the constant attribute is added to every request the study decides, XPA's included.
One value per attribute is the request shape XPA's own generator produces
(`RequestBuilder.buildRequest` writes `getDomain().get(0)`, line 22 at the pinned commit).
Requests that give one attribute several values are outside the universe, and a secondary check
measures how much that matters.

## The witness space

For each attribute designator (category, attribute identifier, data type) a policy reads, the
candidates are every literal it is compared with, `t - 1`, `t` and `t + 1` for every order
threshold `t`, one fresh value of its type, and absent. A cell is one candidate per designator,
and every cell is a request.

## Decisions, atoms and the quotient

Balana decides the policy and every mutant on every cell. Each `Match` element and each
comparison in a condition is an atom, decided on every cell as its own one-rule `Permit` policy:
`Permit` is true, `NotApplicable` false, `Indeterminate` an error. The quotient classes are the
cells grouped by their atoms' values. The policy's decision must be constant on every class; a
policy failing that is excluded and reported.

## Completeness, checked adversarially

For each policy, 200 requests drawn from the candidates perturbed -- fresh strings, thresholds
moved by up to 2, attributes made absent or present -- and every request of every XPA suite for
the policy are decided as the cells are. A mutant that differs from the policy on one of them
and on no cell, or a request whose atom values no cell has, fails the policy, which is excluded
by name.

## The mutants

XPA's own: `PolicyMutator.createAllMutants()` at the pinned commit, which applies PTT, PTF, CRC,
CRE, RER, ANR, RTT, RTF, RCT, RCF, FPR, FDR, ANF, RNF and RPTE (its RTR and RPCE are empty
there). A mutant Balana's reader rejects is unrunnable, counted and excluded. A mutant no cell
separates from its policy is equivalent: counted, reported by operator, and excluded from every
score.

## The strategies

- **XPA's seven generators**, called as XPA's own test panel calls them
  (`org.seal.xacml.gui.TestPanel` at the pinned commit): RC (`RuleCoverage`), DC
  (`DecisionCoverage` with errors), NE-DC (without), MC/DC (`MCDC` with errors), NE-MC/DC
  (without), PC (`RulePairCoverage`) and PD-PC (`RulePairCoverage`, permit--deny pairs). Each
  yields one suite of requests per policy. A suite detects a mutant when Balana decides some
  request in it differently for the mutant than for the policy. A generator that fails, or runs
  longer than 30 minutes, on a policy is recorded, and that criterion has no suite there.
- **The paper's strategies**, in closed form as in its other payoff studies: one witness per
  quotient class, one per decision the policy makes, random suites of those two sizes drawn
  uniformly from the cells, and one witness per cell of the common refinement.
- **For each XPA suite, a random suite of the same size**, drawn uniformly from the cells, in
  closed form.

## Outcomes

For each policy and strategy: the mean detection over the policy's live mutants, and the suite
size.

**Primary.** Two families of paired comparisons over the eligible policies, each with the mean
difference, a bootstrap 95% interval (10,000 resamples) and an exact two-sided sign-flip test
over all sign patterns, with Holm's correction within the family; seed 20261004.
- **H1**, for each of the seven criteria: the quotient against the criterion.
- **H2**, for each of the seven criteria: the criterion against a random suite of its own size.

With eleven policies the smallest attainable two-sided p is about 0.001, so the pooled figures
carry the description.

**Secondary, descriptive.** The same pooled over mutants; by operator; the equivalent mutants by
operator and policy; and the bag check: for each policy, the mutants equivalent in the universe
that one of 200 drawn requests giving each attribute zero to three candidate values separates.

**Prediction**, stated before the run: the quotient detects nearly every live mutant in
expectation, as on the paper's other populations; MC/DC comes close to it with far fewer
requests on policies this small; rule coverage is far below. A criterion within a point of the
quotient is a finding about the criterion, not a failure of the quotient.

## What follows from the result

Results are reported as found, and any deviation from this protocol is recorded in the artifact.

## The policies

| File | Combining algorithm | Rules | Membership | Designators | Cells | Status |
|---|---|---|---|---|---|---|
| `conference3-dup.xml` | deny-unless-permit | 15 | inside | 2 | 40 | eligible |
| `conference3-fa-wdeny.xml` | first-applicable | 15 | inside | 2 | 40 | eligible |
| `conference3-pud.xml` | permit-unless-deny | 15 | inside | 2 | 40 | eligible |
| `conference3.xml` | permit-overrides | 15 | inside | 2 | 40 | eligible |
| `fedora-rule3-po.xml` | permit-overrides | 2 | inside | 3 | 36 | eligible |
| `fedora-rule3.xml` | deny-overrides | 12 | inside | 4 | 594 | eligible |
| `gpms.xml` | permit-overrides | 97 | outside | -- | -- | excluded: outside the fragment: it selects over request content with XPath |
| `HL7.xml` | first-applicable | 19 | outside | -- | -- | excluded: outside the fragment: it reads the clock |
| `itrust3-10.xml` | first-applicable | 640 | inside | 3 | 390,528 | excluded: over the cap (a scaled copy of itrust3) |
| `itrust3-20.xml` | first-applicable | 1280 | inside | 3 | 1,537,008 | excluded: over the cap (a scaled copy of itrust3) |
| `itrust3-40.xml` | first-applicable | 2560 | inside | 3 | 170,560,775 | excluded: over the cap (a scaled copy of itrust3) |
| `itrust3-5.xml` | first-applicable | 320 | inside | 3 | 100,788 | excluded: over the cap (a scaled copy of itrust3) |
| `itrust3.xml` | first-applicable | 64 | inside | 3 | 4,653 | eligible |
| `kmarket-blue-policy.xml` | deny-overrides | 4 | inside | 4 | 375 | eligible |
| `kmarket-gold-policy.xml` | deny-overrides | 3 | inside | 4 | 225 | eligible |
| `kmarket-sliver-policy.xml` | deny-overrides | 5 | inside | 4 | 600 | eligible |
| `obligation3.xml` | permit-overrides | 2 | inside | -- | -- | excluded: inside, not exact-eligible: a regular-expression match |
| `pluto3.xml` | permit-overrides | 21 | inside | 3 | 1,656 | eligible |
| `Simpson1.xml` | permit-unless-deny | 4 | inside | -- | -- | excluded: inside, not exact-eligible: one attribute minus another, compared |
| `Simpson2.xml` | deny-unless-permit | 4 | inside | -- | -- | excluded: inside, not exact-eligible: one attribute minus another, compared |
