# Decision-Class Coverage — research prospectus

**Prepared for supervisor review**
Lead: Mohammad Thabet Hassan · Instrument: `scripts/policy_mutation.py` · Measured: 4 September 2026

A security policy test suite that never expects a permission cannot notice a policy that
grants one. This is measurable, exactly decidable, and — on the evidence so far — the
normal condition of agent-security suites.

---

## 1. The claim

For an ordered first-match policy over a finite label domain, the policy induces a finite
partition of its subject space. A mutant is therefore fully described by the decision it
returns for each cell, so two mutants agreeing everywhere are equivalent *by construction*:
mutation adequacy can be **computed** rather than estimated.

Decision-class coverage follows. A suite that never expects a given decision cannot
distinguish a policy that returns it from one that does not, regardless of how many cases
the suite holds.

We prove coverage necessary for adequacy, show it is **not** implied by the structural
coverage that `opa test --coverage` and the XACML literature already report, and measure it
across policy suites in several ecosystems. The claim we expect to defend is that
agent-security suites are **permit-blind**: they measure restrictiveness only.

---

## 2. Why this is not a tool paper

TrustWeave is the instrument, not the contribution. A tool paper needs adoption or a novel
technique; a policy linter with four stars has neither, and a reviewer would rightly ask
what it does that existing agent guardrails do not. The contribution here stands without
the tool — it is a property of policy test suites, demonstrated on artifacts that already
exist in the wild.

The `discover` command is **cut from this paper**. It scores 0.583 accuracy against its own
labelled benchmark, and an instrument that weak cannot carry a journal claim. It appears
only in threats-to-validity, as a worked example of an assurance pipeline failing open.

---

## 3. Evidence already in hand

Every figure below was produced by the committed instrument and is reproducible with:

```bash
python scripts/policy_mutation.py \
  --policy policies/default-policy.json \
  --scenarios scenarios/default-scenarios.json \
              scenarios/adversarial-scenarios.json \
              scenarios/coverage-matrix-scenarios.json
```

Thirty-eight single-edit mutants of the reference policy. **Sixteen are provably
equivalent** by enumerating the twelve-cell partition — 42.1% of the population discarded
by decision procedure rather than heuristic or manual inspection. Twenty-two remain
observable.

| Suite | Cases | Cells | Mutants killed | Score | Decision class missing |
|---|---:|---:|---:|---:|---|
| `default-scenarios` | 5 | 5/12 | 14/22 | **63.6%** | none |
| `adversarial-scenarios` (OWASP LLM Top 10 · MITRE ATLAS) | 25 | 3/12 | 8/22 | **36.4%** | **allow** |
| `coverage-matrix-scenarios` | 12 | 12/12 | 22/22 | **100%** | none |

**A five-case suite catches nearly twice what a twenty-five-case suite does.** That single
row answers the obvious objection — that a larger suite trivially kills more — before a
reviewer raises it. Case count is not coverage; the last column says why.

### 3.1 The sharpest instance

Change `default_decision` from `deny` to `allow` — a policy that permits everything not
explicitly denied. The 25-case suite, mapped to OWASP and MITRE ATLAS, passes it **25/25**.
The 5-case suite catches it.

Every mutant surviving the adversarial suite is a permissiveness-increasing edit. Its
discriminating power is confined entirely to the restrictive half of the decision space —
which is the half that matters least, because an over-restrictive policy fails loudly in
production and an over-permissive one does not fail at all.

### 3.2 The partition, and what the adversarial suite witnesses

`*` marks a cell the 25-case adversarial suite ever exercises.

| | read | write | sensitive | external |
|---|---|---|---|---|
| **trusted** | allow | deny | deny | deny |
| **conditional** | deny | deny | `*` deny | `*` approval |
| **untrusted** | deny | deny | `*` deny | `*` deny |

Twenty-five cases collapse onto **three distinct engine inputs**. The suite is large and
narrow at once, and no amount of adding cases in the same three cells would change what it
can detect.

---

## 4. Contributions

| | Contribution | Status |
|---|---|---|
| **C1** | Decision-class coverage: definition, theorem, decision procedure | needs work |
| **C2** | Exact mutation adequacy without equivalent-mutant approximation | **have it** |
| **C3** | The negative result, generalised off our own artifact | needs work |
| **C4** | Measurement across Rego/OPA, Cedar, Kubernetes admission policy, agent suites | **must build** |
| **C5** | Threats-to-validity result on assurance tooling | **have it** |

**C1.** Coverage of a suite over a policy is the fraction of reachable partition cells
witnessed with a tight expectation. Total coverage pins the policy to observational
equivalence; zero `allow` expectations makes deny-everything indistinguishable. The
subsumption machinery already exists in `policy_predicates.py`. The proof must be stated
for a defined language fragment, not "policies in general".

**C2.** 38 mutants, 16 discarded by enumeration. This is the technical delta against the
XACML mutation literature, where the equivalent-mutant problem has forced approximation
since Martin & Xie (2007).

**C4.** The empirical body, and the principal risk.

**C5.** Our own analyzer degraded toward `read` on unrecognised code at high confidence,
and `read` is the sole cell the reference policy permits. Neither component was
individually wrong; composed, the pipeline failed open. Two pages, explicitly not claimed
as a contribution.

---

## 5. What a hostile reviewer says first

Written down so the introduction can answer it, rather than the rebuttal.

**"This is Android permission analysis with a new noun."**
Felt et al., Stowaway, PScout. Fair, and it is the first comparison a security reviewer
reaches for. The answer must be in the introduction: agent tool surfaces are dynamically
dispatched, framework-mediated, and trust-labelled by a human rather than declared in a
fixed manifest format — so refusal carries information Android permission analysis never
needed. That answer has to be demonstrated, not asserted.

**"You are measuring conformance to a specification you invented."**
The declaration model is ours. The paper must be framed as measuring an underlying
property — whether a suite can detect a policy change — which is true of Rego, Cedar and
Gatekeeper suites nobody here designed. This is why C4 is load-bearing, not optional.

**"A bigger suite obviously kills more mutants."**
Answered by our own data: the 5-case suite kills 14, the 25-case suite kills 8. Put the
table in the abstract.

---

## 6. Plan

| # | Work | Depends on | Effort |
|---|---|---|---|
| T1 | Harden the mutation harness: operator set as data, exhaustive equivalence by enumeration, deterministic JSON output | — | 3 days |
| T2 | Define the analyzable fragment; enumerate the full attribute space, not the 12-cell projection | T1 | 1 week |
| T3 | **Orthogonality witness**: a Rego policy with 100% structural coverage and 0% permit coverage, and the converse | T2 | 1 day |
| T4 | Suite adapters — Rego/OPA, Cedar, Gatekeeper/Kyverno, agent-security suites — each reporting its own extraction failure rate | T1 | 2.5 weeks |
| T5 | Corpus mining and measurement | T4 | 2 weeks |
| T6 | Theorem and proof over the T2 fragment, with an undecidability note for the unrestricted case | T2 | 1 week |

**T3 is one afternoon and it is non-negotiable.** If decision-class coverage turns out to be
implied by the structural coverage `opa test --coverage` already reports, there is no
contribution and the project should stop. Establishing orthogonality before investing three
weeks in T4 is the cheapest possible way to find that out.

---

## 7. Venue

**Computers & Security** (Elsevier) as primary: it accepts empirical tool-supported
security studies, and the artifact-plus-measurement shape fits its scope.
**Empirical Software Engineering** as fallback if the paper leans further toward the
measurement study than the theorem. Both expect a released artifact and a reproducibility
package, which this repository already supports.

A workshop paper on C2 and C3 alone, submitted first, would timestamp the result and cost
little. An arXiv preprint costs nothing and should go up as soon as T3 confirms
orthogonality.

---

## 8. The three things most likely to sink it

**T3 fails.** If structural coverage already implies decision-class coverage, C1 collapses.
Do T3 first, before anything expensive.

**The corpus is not there.** C4 assumes enough public policy suites exist with extractable
expectations across four ecosystems. If Cedar and Kyverno yield too few, the paper narrows
to Rego plus agent-security suites and the claim weakens from "ecosystems" to "two
ecosystems". Measure corpus size before building four adapters.

**Overclaiming from an unvalidated instrument.** The XCS result in a sibling project
correlated with raw model confidence at r = 1.000 — a novel three-term metric that turned
out to be a rescaling of a baseline. Every number here must come from an instrument
validated against ground truth, with precision, recall and refusal reported. That mistake
is survivable in a repository and fatal at review.

---

## 9. If only one thing happens

Do T3. Everything else is contingent on decision-class coverage being genuinely orthogonal
to the coverage tooling already reports, and that costs one afternoon to settle. If it
holds, this is a paper. If it does not, you will have learned it for the price of a day
rather than a semester.

---

## Prior work to cite and distinguish

- Martin & Xie, "A fault model and mutation testing of access control policies", WWW 2007 —
  the equivalent-mutant problem this work sidesteps.
- Felt et al. on Android permission over-declaration; the Stowaway and PScout
  permission-mapping line — the closest methodological ancestor, and the comparison a
  reviewer will make first.
- OWASP GenAI LLM Top 10 and MITRE ATLAS — the frameworks the measured agent suites map to,
  and part of the explanation for why those suites are permit-blind: both are threat
  catalogues, and a threat catalogue enumerates what must be refused.
