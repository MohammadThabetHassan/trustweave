# Lean 4 mechanisation of the quotient results

This directory holds machine-checked proofs, in Lean 4 with Mathlib, of the core results of
three sections of the TrustWeave journal manuscript: "The quotient, and what is exact within
it", "The evaluation rule does not matter" and "Where the fragment ends". Results are cited by
their titles in the manuscript. Every proof is complete: `lake build` exits 0, and the axiom
audit at the end of this file shows only Lean's three standard axioms.

Formalising the statements turned up three places where the manuscript says less, or something
slightly different, than what is true. They are listed under "Imprecisions in the manuscript"
below, each with a machine-checked counterexample or correction.

## Versions

| Item | Value |
|---|---|
| Lean toolchain (`lean-toolchain`) | `leanprover/lean4:v4.34.1` |
| Mathlib (`lake-manifest.json`) | tag `v4.34.1`, commit `d13f23b723b8a846827a245b89c10fc7d3f11612` |

All dependencies, as pinned in `lake-manifest.json`:

| Package | Commit | Requested revision |
|---|---|---|
| `mathlib` | `d13f23b723b8a846827a245b89c10fc7d3f11612` | `v4.34.1` |
| `plausible` | `118aa17ee84656b8bd727fef7c458ee8c833385c` | `main` |
| `LeanSearchClient` | `ddf04cf3949fa556442341e87d47f9f6e6074707` | `main` |
| `importGraph` | `e928b72544873815af278d38681b31c0293588e3` | `main` |
| `proofwidgets` | `106ff4fafc74ef4ac99d81dbf3ab399118f497a5` | `main` |
| `aesop` | `355695d523e41d0554926416cba2a2b3544fbbc9` | `master` |
| `Qq` | `6a489d9af5d0c47e5b259e2e8bcdfc1811b5a259` | `master` |
| `batteries` | `f2effa3d803fda822b1f97b806c47cf2adfbcbc2` | `main` |
| `Cli` | `e92c9f15fdfacc8536f31cfb3b7ad26c3c8cd204` | `v4.34.0` |

## Building

Build in a copy of this directory **outside** any checkout of the repository. Lake keeps
Mathlib under `.lake/`, about 7.7 GB including thousands of Markdown files with relative
links. The repository's Markdown link check (`_check_markdown_links` in
`scripts/reality_check.py`) scans every `*.md` below the repository root and does not skip
`.lake/`, so a build in place makes that check fail. The `.gitignore` here keeps `.lake/` out
of git, but the link check does not consult git.

```sh
# elan, the Lean toolchain manager, installed without root and without a default toolchain
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
export PATH="$HOME/.elan/bin:$PATH"

# from the repository root: copy the sources out, then build there
mkdir -p ~/trustweave-lean-build
cp -r proofs/lean/. ~/trustweave-lean-build
cd ~/trustweave-lean-build
lake exe cache get      # prebuilt Mathlib for the pinned commit
lake build              # must exit 0; the build also runs the axiom audit
lake env lean TrustweaveLean/Audit.lean    # prints the audit shown at the end of this file
```

`lake build` compiles every module, including `TrustweaveLean/Audit.lean`. Besides printing
`#print axioms` for each theorem, that file ends with a check that fails the build if any
theorem in the `TrustWeave` namespace, including the lemmas Lean generates itself, depends on
an axiom other than `propext`, `Classical.choice` and `Quot.sound`.

## Layout

| File | Contents |
|---|---|
| `TrustweaveLean/Basic.lean` | policies, the equivalence `~P`, suites, `Δ` |
| `TrustweaveLean/Quotient.lean` | finite quotient; combining-rule independence |
| `TrustweaveLean/Kill.lean` | exact kill criterion; coverage decides the score; semantic mutants |
| `TrustweaveLean/Achievable.lean` | which values existential guards achieve (general form, purpose sets) |
| `TrustweaveLean/Patterns.lean` | capability patterns, dominance, and the pattern reading of the same lemma |
| `TrustweaveLean/PrefixChain.lean` | prefix patterns are cheaper than they look |
| `TrustweaveLean/Undecidable.lean` | undecidability with a step-bounded halting guard; its cell count |
| `TrustweaveLean/Counterexamples.lean` | counterexamples for hypotheses the manuscript leaves out |
| `TrustweaveLean/Audit.lean` | `#print axioms` for every theorem, and the build-time axiom check |
| `TrustweaveLean.lean` | imports all of the above |

## Theorem map

Every theorem in the development, with the manuscript result it formalises. The statement of
each is reproduced verbatim from the source in "Statements" below, in the same grouping.

| Lean theorem | Manuscript result | What it states |
|---|---|---|
| `TrustWeave.Policy.finite_cells` | Theorem "Finite quotient" | the quotient `S/~P` is finite |
| `TrustWeave.Policy.sem_eq_of_sim` | Theorem "Finite quotient" | `⟦P⟧` is constant on each cell |
| `TrustWeave.Policy.sim_le_ker_sem` | Theorem "Finite quotient" | the same, as a refinement of the kernel of `⟦P⟧` |
| `TrustWeave.Policy.cellSem_mk` | Theorem "Finite quotient" | the same, as a factorisation through the quotient |
| `TrustWeave.Policy.cellOutcome_injective` | Theorem "Finite quotient" | proof step: `~P` is the kernel of the outcome map |
| `TrustWeave.Policy.card_cells_le` | Theorem "Combining-rule independence" | at most `Fintype.card V ^ n` cells |
| `TrustWeave.Policy.sim_eq_of_guard_eq` | Theorem "Combining-rule independence" | the quotient depends on the guards only |
| `TrustWeave.combining_rule_independence` | Theorem "Combining-rule independence" | all of the above for an arbitrary combining function, bundled |
| `TrustWeave.Policy.card_cells_eq_card_achieved` | Remark "The bound is not a count" | cells correspond exactly to achieved outcome vectors |
| `TrustWeave.kill_criterion` | Theorem "Exact kill criterion" | policy and mutant given by their semantics |
| `TrustWeave.exact_kill_criterion` | Theorem "Exact kill criterion" | paper form; the mutant is any policy |
| `TrustWeave.coverage_decides_score` | Corollary "Coverage decides the score" | general form: any equivalence refining the kernels |
| `TrustWeave.coverage_decides_score_policies` | Corollary "Coverage decides the score" | paper form: `≈` is the common refinement |
| `TrustWeave.commonRefinement_iff` | Corollary "Coverage decides the score" | the common refinement is the meet of the equivalences |
| `TrustWeave.commonRefinement_eq_ker` | Corollary "Coverage decides the score" | it is `~` of the concatenated guards |
| `TrustWeave.finite_commonRefinement` | Corollary "Coverage decides the score" | it is finite for finitely many mutants |
| `TrustWeave.semantic_mutants` | Corollary "Semantic mutants: coverage of the quotient is exactly right" | paper form, with `Nontrivial D` added |
| `TrustWeave.semantic_mutants_sufficiency` | Corollary "Semantic mutants: coverage of the quotient is exactly right" | the if direction, without `Nontrivial D` |
| `TrustWeave.semantic_mutants_constant_on_cells` | Corollary "Semantic mutants: coverage of the quotient is exactly right" | mutants as functions `S → D` constant on cells |
| `TrustWeave.semantic_mutants_general` | Corollary "Semantic mutants: coverage of the quotient is exactly right" | general form over any equivalence |
| `TrustWeave.semantic_mutants_sufficiency_general` | Corollary "Semantic mutants: coverage of the quotient is exactly right" | general form, if direction |
| `TrustWeave.semantic_mutants_necessity_general` | Corollary "Semantic mutants: coverage of the quotient is exactly right" | general form, only-if direction |
| `TrustWeave.semantic_mutants_iff_fails_with_one_decision` | Corollary "Semantic mutants: coverage of the quotient is exactly right" | counterexample: one decision |
| `TrustWeave.semantic_mutants_necessity_fails_without_consistency` | Corollary "Semantic mutants: coverage of the quotient is exactly right" | counterexample: inconsistent suite, only-if direction |
| `TrustWeave.semantic_mutants_sufficiency_fails_without_consistency` | Corollary "Semantic mutants: coverage of the quotient is exactly right" | counterexample: inconsistent suite, if direction |
| `TrustWeave.achievable_iff` | Lemma "Which values existential guards achieve" | general form |
| `TrustWeave.achieves_witness` | Lemma "Which values existential guards achieve" | the witness set `{xᵢ : vᵢ = 1}` |
| `TrustWeave.achievable_iff_purpose` | Lemma "Which values existential guards achieve" | purpose-set reading |
| `TrustWeave.achievable_iff_no_dominance` | Lemma "Which values existential guards achieve" | capability-pattern reading, with the separator hypothesis |
| `TrustWeave.Pattern.dominates_iff_synDominates` | Lemma "Which values existential guards achieve" | the lemma's description of dominance |
| `TrustWeave.dominance_reading_fails_without_separator` | Lemma "Which values existential guards achieve" | counterexample: pattern reading without the separator hypothesis |
| `TrustWeave.prefix_patterns_card_le` | Lemma "Prefix patterns are cheaper than they look" | at most `n + 1` achieved vectors |
| `TrustWeave.prefixOutcome_mem` | Lemma "Prefix patterns are cheaper than they look" | proof step: a chain is fixed by its longest member |
| `TrustWeave.policy_equivalence_undecidable` | Theorem `thm:undecidable` (untitled; opens "Where the fragment ends") | no computable decision procedure, uniform in `e` |
| `TrustWeave.haltPolicy_equiv_deny_iff` | Theorem `thm:undecidable` (untitled; opens "Where the fragment ends") | proof step: `⟦P_e⟧ = ⟦Q⟧` iff `e` does not halt on `0` |
| `TrustWeave.haltPolicy_card_cells_eq_one_iff` | Remark "Which clause of Definition `def:refining` fails" | correction: one cell iff `e` does not halt |
| `TrustWeave.haltPolicy_card_cells_eq_two_iff` | Remark "Which clause of Definition `def:refining` fails" | correction: two cells iff `e` halts |
| `TrustWeave.guardSim_iff` | Definition "Policy-relative equivalence" | supporting: unfolds `guardSim` |
| `TrustWeave.Policy.sim_iff` | Definition "Policy-relative equivalence" | supporting: unfolds `~P` |
| `TrustWeave.Policy.sem_eq_combine_outcome` | (supporting) | `⟦P⟧ s = c (outcome vector)` |
| `TrustWeave.Suite.covers_iff` | Definition "Suites, witnessing, killing" | supporting: covering stated per subject |
| `TrustWeave.Policy.cellOutcome_mk` | (supporting) | computation rule for `cellOutcome` |
| `TrustWeave.setoid_iInf_iff` | (supporting) | membership in an indexed meet of equivalences |
| `TrustWeave.exists_haltsWithin_iff` | (supporting) | halting within some step bound iff halting |
| `TrustWeave.haltsWithin_zero` | (supporting) | nothing halts within zero steps |

## Definitions

The setting is that of Theorem "Combining-rule independence": subjects, decisions and guard
outcomes are arbitrary types `S`, `D` and `V`, and a policy is any `n` guards with any
combining function. The variable lines in force are `variable {S D V : Type*} {n : ℕ}` in
`Basic.lean` and `Quotient.lean`, `variable {S D : Type*}` in `Kill.lean` and
`Undecidable.lean` (which also has `open Nat.Partrec`), `variable {α : Type*} {k : ℕ}` in
`Achievable.lean`, and `variable {α : Type*}` in `Patterns.lean` and `PrefixChain.lean`.

Policies, semantics and the policy-relative equivalence (`Basic.lean`):

```lean
/-- A policy over subjects `S` and decisions `D`: `n` guards, guard `i` reporting
`guard i s : V` at subject `s`, and a combining function on the vector of guard outcomes. -/
structure Policy (S D V : Type*) (n : ℕ) where
  /-- The guards `g₁, …, gₙ`. -/
  guard : Fin n → S → V
  /-- The combining function `c : Vⁿ → D`. -/
  combine : (Fin n → V) → D
```

```lean
/-- The equivalence a guard family induces on subjects: two subjects are related when every
guard gives them the same value. It is the kernel of the guard-outcome map, and it mentions
no combining function. -/
def guardSim (g : Fin n → S → V) : Setoid S :=
  Setoid.ker fun s i => g i s
```

```lean
/-- The guard-outcome vector `(g₁ s, …, gₙ s)` of a subject. -/
def outcome (P : Policy S D V n) (s : S) : Fin n → V :=
  fun i => P.guard i s
```

```lean
/-- The semantics `⟦P⟧ s = c (fun i => g i s)`. -/
def sem (P : Policy S D V n) (s : S) : D :=
  P.combine fun i => P.guard i s
```

```lean
/-- The policy-relative equivalence `~P`: `s ~P s'` iff `∀ i, g i s = g i s'`. Its classes
are the paper's *cells*, and `Quotient P.sim` is the paper's `S/~P`. -/
def sim (P : Policy S D V n) : Setoid S :=
  guardSim P.guard
```


Suites, witnessing, consistency, covering, killing and `Δ` (`Basic.lean`). Covering is stated
over the quotient: every class contains a witnessed subject.

```lean
/-- A suite: a finite set of `(subject, decision)` pairs. -/
abbrev Suite (S D : Type*) :=
  Finset (S × D)
```

```lean
/-- `W(Σ) = {s | (s, d) ∈ Σ for some d}`, the subjects a suite witnesses. -/
def witnessed (T : Suite S D) : Set S :=
  {s | ∃ d, (s, d) ∈ T}
```

```lean
/-- A suite is consistent with a semantics `f` when `d = f s` for every pair `(s, d)`. -/
def Consistent (T : Suite S D) (f : S → D) : Prop :=
  ∀ s d, (s, d) ∈ T → d = f s
```

```lean
/-- A suite covers an equivalence `r` when `W(Σ)` meets every `r`-class: every class
contains the subject of some pair. -/
def Covers (T : Suite S D) (r : Setoid S) : Prop :=
  ∀ c : Quotient r, ∃ s ∈ T.witnessed, Quotient.mk r s = c
```

```lean
/-- A suite kills a mutant (given by its semantics `m`) when `m s ≠ d` for some pair. -/
def Kills (T : Suite S D) (m : S → D) : Prop :=
  ∃ s d, (s, d) ∈ T ∧ m s ≠ d
```

```lean
/-- `Δ(P, M) = {s | ⟦P⟧ s ≠ ⟦M⟧ s}`, for semantics `p` and `m`. -/
def Delta (p m : S → D) : Set S :=
  {s | p s ≠ m s}
```


The common refinement used by Corollary "Coverage decides the score" (`Kill.lean`):

```lean
/-- The common refinement of `~P` and of `~M` for every mutant `M` of a family: the meet, in
the lattice of equivalence relations, of all those equivalences. -/
def commonRefinement {ι V : Type*} {n : ℕ} {W : ι → Type*} {k : ι → ℕ}
    (P : Policy S D V n) (M : ∀ j, Policy S D (W j) (k j)) : Setoid S :=
  P.sim ⊓ ⨅ j, (M j).sim
```


Achieving a value with existential guards (`Achievable.lean`):

```lean
/-- `K` achieves `v` for the existential guards `gᵢ(K) ≡ ∃ x ∈ K, m i x`: each guard holds
at `K` exactly when `v` marks it `true`. -/
def Achieves (m : Fin k → α → Prop) (K : Finset α) (v : Fin k → Bool) : Prop :=
  ∀ i, (∃ x ∈ K, m i x) ↔ v i = true
```


Capability patterns (`Patterns.lean`):

```lean
/-- A capability pattern: a literal, or a stem followed by a final wildcard. -/
inductive Pattern (α : Type*) where
  /-- A literal; it matches exactly itself. -/
  | lit : List α → Pattern α
  /-- A stem followed by a final wildcard; it matches every string the stem prefixes. -/
  | wild : List α → Pattern α
```

```lean
/-- Matching: a literal as equality, a final-wildcard pattern as a prefix test on its stem. -/
def Matches : Pattern α → List α → Prop
  | lit l, x => x = l
  | wild st, x => st <+: x
```

```lean
/-- `q` dominates `q'` when every string matching `q'` matches `q`. -/
def Dominates (q q' : Pattern α) : Prop :=
  ∀ x, q'.Matches x → q.Matches x
```

```lean
/-- The paper's syntactic description of dominance: a final wildcard with stem `st` dominates
every pattern whose literal or stem extends `st`, and a literal dominates only itself. -/
def SynDominates : Pattern α → Pattern α → Prop
  | wild st, lit l => st <+: l
  | wild st, wild st' => st <+: st'
  | lit l, lit l' => l = l'
  | lit _, wild _ => False
```


The step-bounded halting guard and the two policies of the reduction (`Undecidable.lean`):

```lean
/-- `e` halts on input `0` within `k` steps, read off Mathlib's fuel-bounded evaluator. -/
def haltsWithin (e : Code) (k : ℕ) : Bool :=
  (Code.evaln k e 0).isSome
```

```lean
/-- `P_e`: one guard, "`e` halts on `0` within `len s` steps"; decision `allow` when the guard
holds and `deny` otherwise. -/
def haltPolicy (len : S → ℕ) (allow deny : D) (e : Code) : Policy S D Bool 1 where
  guard := fun _ s => haltsWithin e (len s)
  combine := fun v => if v 0 = true then allow else deny
```

```lean
/-- The policy with no guards that decides `deny` everywhere. -/
def denyPolicy (deny : D) : Policy S D Bool 0 where
  guard := fun i => i.elim0
  combine := fun _ => deny
```


## Statements

### Theorem "Finite quotient" (abstract part) and Theorem "Combining-rule independence"

The quotient by `~P` is finite, has at most `|V|^n` cells, and `⟦P⟧` is constant on every
cell, for an arbitrary combining function `c`.

`TrustWeave.Policy.finite_cells` (`TrustweaveLean/Quotient.lean`):

```lean
theorem finite_cells [Finite V] (P : Policy S D V n) : Finite (Quotient P.sim)
```

`TrustWeave.Policy.card_cells_le` (`TrustweaveLean/Quotient.lean`):

```lean
theorem card_cells_le [Fintype V] (P : Policy S D V n) :
    Nat.card (Quotient P.sim) ≤ Fintype.card V ^ n
```

`TrustWeave.Policy.sem_eq_of_sim` (`TrustweaveLean/Quotient.lean`):

```lean
theorem sem_eq_of_sim (P : Policy S D V n) {s s' : S} (h : P.sim s s') :
    P.sem s = P.sem s'
```

`TrustWeave.Policy.sim_le_ker_sem` (`TrustweaveLean/Quotient.lean`):

```lean
theorem sim_le_ker_sem (P : Policy S D V n) : P.sim ≤ Setoid.ker P.sem
```

`TrustWeave.Policy.cellSem_mk` (`TrustweaveLean/Quotient.lean`):

```lean
theorem cellSem_mk (P : Policy S D V n) (s : S) :
    P.cellSem (Quotient.mk P.sim s) = P.sem s
```

`TrustWeave.Policy.cellOutcome_injective` (`TrustweaveLean/Quotient.lean`):

```lean
theorem cellOutcome_injective (P : Policy S D V n) : Function.Injective P.cellOutcome
```

`TrustWeave.Policy.sim_eq_of_guard_eq` (`TrustweaveLean/Quotient.lean`):

```lean
theorem sim_eq_of_guard_eq {P P' : Policy S D V n} (h : P.guard = P'.guard) :
    P.sim = P'.sim
```

`TrustWeave.combining_rule_independence` (`TrustweaveLean/Quotient.lean`):

```lean
theorem combining_rule_independence [Fintype V] (g : Fin n → S → V) (c : (Fin n → V) → D) :
    (Policy.mk g c).sim = guardSim g ∧
    Finite (Quotient (Policy.mk g c).sim) ∧
    Nat.card (Quotient (Policy.mk g c).sim) ≤ Fintype.card V ^ n ∧
    ∀ s s' : S, (Policy.mk g c).sim s s' → (Policy.mk g c).sem s = (Policy.mk g c).sem s'
```


Remark "The bound is not a count": the number of cells is the number of outcome vectors some
subject achieves, not `|V|^n`.

`TrustWeave.Policy.card_cells_eq_card_achieved` (`TrustweaveLean/Quotient.lean`):

```lean
theorem card_cells_eq_card_achieved (P : Policy S D V n) :
    Nat.card (Quotient P.sim) = Nat.card (Set.range P.outcome)
```


### Theorem "Exact kill criterion"

`TrustWeave.kill_criterion` (`TrustweaveLean/Kill.lean`):

```lean
theorem kill_criterion (p m : S → D) (T : Suite S D) (hT : T.Consistent p) :
    T.Kills m ↔ Delta p m ∩ T.witnessed ≠ ∅
```

`TrustWeave.exact_kill_criterion` (`TrustweaveLean/Kill.lean`):

```lean
theorem exact_kill_criterion {V W : Type*} {n k : ℕ} (P : Policy S D V n)
    (M : Policy S D W k) (T : Suite S D) (hT : T.Consistent P.sem) :
    T.Kills M.sem ↔ Delta P.sem M.sem ∩ T.witnessed ≠ ∅
```


### Corollary "Coverage decides the score"

`TrustWeave.coverage_decides_score` (`TrustweaveLean/Kill.lean`):

```lean
theorem coverage_decides_score {ι : Type*} (p : S → D) (m : ι → S → D) (r : Setoid S)
    (hp : r ≤ Setoid.ker p) (hm : ∀ j, r ≤ Setoid.ker (m j))
    (T : Suite S D) (hT : T.Consistent p) (hcov : T.Covers r) :
    ∀ j, m j ≠ p → T.Kills (m j)
```

`TrustWeave.coverage_decides_score_policies` (`TrustweaveLean/Kill.lean`):

```lean
theorem coverage_decides_score_policies {ι V : Type*} {n : ℕ} {W : ι → Type*} {k : ι → ℕ}
    (P : Policy S D V n) (M : ∀ j, Policy S D (W j) (k j)) (T : Suite S D)
    (hT : T.Consistent P.sem) (hcov : T.Covers (commonRefinement P M)) :
    ∀ j, (M j).sem ≠ P.sem → T.Kills (M j).sem
```

`TrustWeave.commonRefinement_iff` (`TrustweaveLean/Kill.lean`):

```lean
theorem commonRefinement_iff {ι V : Type*} {n : ℕ} {W : ι → Type*} {k : ι → ℕ}
    (P : Policy S D V n) (M : ∀ j, Policy S D (W j) (k j)) (s s' : S) :
    commonRefinement P M s s' ↔ P.sim s s' ∧ ∀ j, (M j).sim s s'
```

`TrustWeave.commonRefinement_eq_ker` (`TrustweaveLean/Kill.lean`):

```lean
theorem commonRefinement_eq_ker {ι V : Type*} {n : ℕ} {W : ι → Type*} {k : ι → ℕ}
    (P : Policy S D V n) (M : ∀ j, Policy S D (W j) (k j)) :
    commonRefinement P M = Setoid.ker fun s => (P.outcome s, fun j => (M j).outcome s)
```

`TrustWeave.finite_commonRefinement` (`TrustweaveLean/Kill.lean`):

```lean
theorem finite_commonRefinement {ι V : Type*} {n : ℕ} {W : ι → Type*} {k : ι → ℕ}
    [Finite ι] [Finite V] [∀ j, Finite (W j)]
    (P : Policy S D V n) (M : ∀ j, Policy S D (W j) (k j)) :
    Finite (Quotient (commonRefinement P M))
```


### Corollary "Semantic mutants: coverage of the quotient is exactly right"

The semantic mutants are all functions `μ : S/~P → D`, acting on subjects by `s ↦ μ [s]`.

`TrustWeave.semantic_mutants` (`TrustweaveLean/Kill.lean`):

```lean
theorem semantic_mutants {V : Type*} {n : ℕ} [Nontrivial D] (P : Policy S D V n)
    (T : Suite S D) (hT : T.Consistent P.sem) :
    (∀ μ : Quotient P.sim → D, (fun s => μ (Quotient.mk P.sim s)) ≠ P.sem →
      T.Kills fun s => μ (Quotient.mk P.sim s)) ↔ T.Covers P.sim
```

`TrustWeave.semantic_mutants_sufficiency` (`TrustweaveLean/Kill.lean`):

```lean
theorem semantic_mutants_sufficiency {V : Type*} {n : ℕ} (P : Policy S D V n) (T : Suite S D)
    (hT : T.Consistent P.sem) (hcov : T.Covers P.sim) :
    ∀ μ : Quotient P.sim → D, (fun s => μ (Quotient.mk P.sim s)) ≠ P.sem →
      T.Kills fun s => μ (Quotient.mk P.sim s)
```

`TrustWeave.semantic_mutants_constant_on_cells` (`TrustweaveLean/Kill.lean`):

```lean
theorem semantic_mutants_constant_on_cells {V : Type*} {n : ℕ} [Nontrivial D]
    (P : Policy S D V n) (T : Suite S D) (hT : T.Consistent P.sem) :
    (∀ m : S → D, P.sim ≤ Setoid.ker m → m ≠ P.sem → T.Kills m) ↔ T.Covers P.sim
```

`TrustWeave.semantic_mutants_general` (`TrustweaveLean/Kill.lean`):

```lean
theorem semantic_mutants_general [Nontrivial D] (p : S → D) (r : Setoid S)
    (hp : r ≤ Setoid.ker p) (T : Suite S D) (hT : T.Consistent p) :
    (∀ μ : Quotient r → D, (fun s => μ (Quotient.mk r s)) ≠ p →
      T.Kills fun s => μ (Quotient.mk r s)) ↔ T.Covers r
```

`TrustWeave.semantic_mutants_sufficiency_general` (`TrustweaveLean/Kill.lean`):

```lean
theorem semantic_mutants_sufficiency_general (p : S → D) (r : Setoid S)
    (hp : r ≤ Setoid.ker p) (T : Suite S D) (hT : T.Consistent p) (hcov : T.Covers r) :
    ∀ μ : Quotient r → D, (fun s => μ (Quotient.mk r s)) ≠ p →
      T.Kills fun s => μ (Quotient.mk r s)
```

`TrustWeave.semantic_mutants_necessity_general` (`TrustweaveLean/Kill.lean`):

```lean
theorem semantic_mutants_necessity_general [Nontrivial D] (p : S → D) (r : Setoid S)
    (hp : r ≤ Setoid.ker p) (T : Suite S D) (hT : T.Consistent p)
    (hkill : ∀ μ : Quotient r → D, (fun s => μ (Quotient.mk r s)) ≠ p →
      T.Kills fun s => μ (Quotient.mk r s)) :
    T.Covers r
```


The hypotheses `Nontrivial D` and `T.Consistent P.sem` cannot be dropped:

`TrustWeave.semantic_mutants_iff_fails_with_one_decision` (`TrustweaveLean/Counterexamples.lean`):

```lean
theorem semantic_mutants_iff_fails_with_one_decision :
    ∃ (P : Policy Unit Unit Bool 0) (T : Suite Unit Unit), T.Consistent P.sem ∧
      (∀ μ : Quotient P.sim → Unit, (fun s => μ (Quotient.mk P.sim s)) ≠ P.sem →
        T.Kills fun s => μ (Quotient.mk P.sim s)) ∧
      ¬ T.Covers P.sim
```

`TrustWeave.semantic_mutants_necessity_fails_without_consistency` (`TrustweaveLean/Counterexamples.lean`):

```lean
theorem semantic_mutants_necessity_fails_without_consistency :
    ∃ (P : Policy Bool Bool Bool 1) (T : Suite Bool Bool),
      (∀ μ : Quotient P.sim → Bool, (fun s => μ (Quotient.mk P.sim s)) ≠ P.sem →
        T.Kills fun s => μ (Quotient.mk P.sim s)) ∧
      ¬ T.Covers P.sim
```

`TrustWeave.semantic_mutants_sufficiency_fails_without_consistency` (`TrustweaveLean/Counterexamples.lean`):

```lean
theorem semantic_mutants_sufficiency_fails_without_consistency :
    ∃ (P : Policy Unit Bool Bool 0) (T : Suite Unit Bool), T.Covers P.sim ∧
      ∃ μ : Quotient P.sim → Bool, (fun s => μ (Quotient.mk P.sim s)) ≠ P.sem ∧
        ¬ T.Kills fun s => μ (Quotient.mk P.sim s)
```


### Lemma "Which values existential guards achieve"

General form, the witness set, and the purpose-set reading:

`TrustWeave.achievable_iff` (`TrustweaveLean/Achievable.lean`):

```lean
theorem achievable_iff (m : Fin k → α → Prop) (v : Fin k → Bool) :
    (∃ K : Finset α, Achieves m K v) ↔
      ∀ i, v i = true → ∃ x, m i x ∧ ∀ j, v j = false → ¬ m j x
```

`TrustWeave.achieves_witness` (`TrustweaveLean/Achievable.lean`):

```lean
theorem achieves_witness [DecidableEq α] (m : Fin k → α → Prop) (v : Fin k → Bool)
    (x : Fin k → α) (hx : ∀ i, v i = true → m i (x i) ∧ ∀ j, v j = false → ¬ m j (x i)) :
    Achieves m ((Finset.univ.filter fun i => v i = true).image x) v
```

`TrustWeave.achievable_iff_purpose` (`TrustweaveLean/Achievable.lean`):

```lean
theorem achievable_iff_purpose (R : Fin k → Set α) (v : Fin k → Bool) :
    (∃ G : Finset α, ∀ l, ((↑G ∩ R l).Nonempty ↔ v l = true)) ↔
      ∀ l, v l = true → ¬ R l ⊆ ⋃ j ∈ {j | v j = false}, R j
```


Capability-pattern reading. The lemma's description of dominance, then the reading itself
under the hypothesis the manuscript's proof uses (every wildcard stem ends with a separator),
then a counterexample without that hypothesis:

`TrustWeave.Pattern.dominates_iff_synDominates` (`TrustweaveLean/Patterns.lean`):

```lean
theorem dominates_iff_synDominates [Nonempty α] (q q' : Pattern α) :
    q.Dominates q' ↔ q.SynDominates q'
```

`TrustWeave.achievable_iff_no_dominance` (`TrustweaveLean/Patterns.lean`):

```lean
open Pattern in
theorem achievable_iff_no_dominance (sep c : α) (hc : c ≠ sep) {k : ℕ}
    (q : Fin k → Pattern α)
    (hsep : ∀ j st, q j = wild st → st = [] ∨ ∃ pre, st = pre ++ [sep]) (v : Fin k → Bool) :
    (∃ K : Finset (List α), Achieves (fun i x => (q i).Matches x) K v) ↔
      ∀ i j, v i = true → v j = false → ¬ (q j).Dominates (q i)
```

`TrustWeave.dominance_reading_fails_without_separator` (`TrustweaveLean/Counterexamples.lean`):

```lean
theorem dominance_reading_fails_without_separator :
    ∃ (q : Fin 4 → Pattern Bool) (v : Fin 4 → Bool),
      (∀ i j, v i = true → v j = false → ¬ (q j).Dominates (q i)) ∧
      ¬ ∃ K : Finset (List Bool), Achieves (fun i x => (q i).Matches x) K v
```


### Lemma "Prefix patterns are cheaper than they look"

`TrustWeave.prefix_patterns_card_le` (`TrustweaveLean/PrefixChain.lean`):

```lean
theorem prefix_patterns_card_le [DecidableEq α] {n : ℕ} (q : Fin n → List α) :
    (Set.range fun s : List α => fun i => decide (q i <+: s)).Finite ∧
      (Set.range fun s : List α => fun i => decide (q i <+: s)).ncard ≤ n + 1
```

`TrustWeave.prefixOutcome_mem` (`TrustweaveLean/PrefixChain.lean`):

```lean
theorem prefixOutcome_mem [DecidableEq α] {n : ℕ} (q : Fin n → List α) (s : List α) :
    prefixOutcome q s = (fun _ => false) ∨ ∃ i, prefixOutcome q s = prefixOutcome q (q i)
```


### Theorem `thm:undecidable` (the untitled theorem opening "Where the fragment ends")

There is no computable decision procedure, uniform in the program `e`, for whether the policy
whose single guard is "`e` halts on `0` within `|s|` steps" is equivalent to the always-deny
policy. Subjects form any type with a length function that takes every value.

`TrustWeave.policy_equivalence_undecidable` (`TrustweaveLean/Undecidable.lean`):

```lean
theorem policy_equivalence_undecidable (len : S → ℕ) (hlen : Function.Surjective len)
    {allow deny : D} (hne : allow ≠ deny) :
    ¬ ComputablePred fun e : Code =>
      (haltPolicy len allow deny e).sem = (denyPolicy deny).sem
```

`TrustWeave.haltPolicy_equiv_deny_iff` (`TrustweaveLean/Undecidable.lean`):

```lean
theorem haltPolicy_equiv_deny_iff (len : S → ℕ) (hlen : Function.Surjective len)
    {allow deny : D} (hne : allow ≠ deny) (e : Code) :
    (haltPolicy len allow deny e).sem = (denyPolicy deny).sem ↔ ¬ (e.eval 0).Dom
```


Remark "Which clause of Definition `def:refining` fails", corrected: the guard `g_e`
induces one cell when `e` does not halt on `0` and two when it does.

`TrustWeave.haltPolicy_card_cells_eq_one_iff` (`TrustweaveLean/Undecidable.lean`):

```lean
theorem haltPolicy_card_cells_eq_one_iff (len : S → ℕ) (hlen : Function.Surjective len)
    (allow deny : D) (e : Code) :
    Nat.card (Quotient (haltPolicy len allow deny e).sim) = 1 ↔ ¬ (e.eval 0).Dom
```

`TrustWeave.haltPolicy_card_cells_eq_two_iff` (`TrustweaveLean/Undecidable.lean`):

```lean
theorem haltPolicy_card_cells_eq_two_iff (len : S → ℕ) (hlen : Function.Surjective len)
    (allow deny : D) (e : Code) :
    Nat.card (Quotient (haltPolicy len allow deny e).sim) = 2 ↔ (e.eval 0).Dom
```


### Supporting lemmas

`TrustWeave.guardSim_iff` (`TrustweaveLean/Basic.lean`):

```lean
theorem guardSim_iff (g : Fin n → S → V) (s s' : S) :
    guardSim g s s' ↔ ∀ i, g i s = g i s'
```

`TrustWeave.Policy.sim_iff` (`TrustweaveLean/Basic.lean`):

```lean
theorem sim_iff (P : Policy S D V n) (s s' : S) :
    P.sim s s' ↔ ∀ i, P.guard i s = P.guard i s'
```

`TrustWeave.Policy.sem_eq_combine_outcome` (`TrustweaveLean/Basic.lean`):

```lean
theorem sem_eq_combine_outcome (P : Policy S D V n) (s : S) :
    P.sem s = P.combine (P.outcome s)
```

`TrustWeave.Suite.covers_iff` (`TrustweaveLean/Basic.lean`):

```lean
theorem covers_iff (T : Suite S D) (r : Setoid S) :
    T.Covers r ↔ ∀ s, ∃ s' ∈ T.witnessed, r s' s
```

`TrustWeave.Policy.cellOutcome_mk` (`TrustweaveLean/Quotient.lean`):

```lean
theorem cellOutcome_mk (P : Policy S D V n) (s : S) :
    P.cellOutcome (Quotient.mk P.sim s) = P.outcome s
```

`TrustWeave.setoid_iInf_iff` (`TrustweaveLean/Kill.lean`):

```lean
theorem setoid_iInf_iff {ι : Type*} (r : ι → Setoid S) (x y : S) :
    (⨅ j, r j) x y ↔ ∀ j, r j x y
```

`TrustWeave.exists_haltsWithin_iff` (`TrustweaveLean/Undecidable.lean`):

```lean
theorem exists_haltsWithin_iff (e : Code) :
    (∃ k, haltsWithin e k = true) ↔ (e.eval 0).Dom
```

`TrustWeave.haltsWithin_zero` (`TrustweaveLean/Undecidable.lean`):

```lean
theorem haltsWithin_zero (e : Code) : haltsWithin e 0 = false
```


## Where the Lean statements differ from the manuscript

1. **The setting is the general one throughout.** Subjects, decisions and guard outcomes are
   arbitrary types `S`, `D`, `V`, and a policy is any guard family `Fin n → S → V` with any
   combining function `(Fin n → V) → D`. The manuscript's concrete language (subjects as tuples
   of labels, strings and finite string sets; first-match semantics with a default) is not
   formalised as such. It is the instance `V = Bool` with first-match as the combining
   function, and Theorem "Combining-rule independence" is the manuscript's own claim that the
   results hold in this generality.
2. **Mutants are semantics.** `Kills`, `Delta`, `kill_criterion` and `coverage_decides_score`
   take the policy and the mutant as functions `S → D`, so any policy's `sem` instantiates
   them, including mutant policies with a different number of guards or a different outcome
   type. `exact_kill_criterion` and `coverage_decides_score_policies` restate the manuscript's
   form with mutants that are policies of arbitrary shape.
3. **Theorem "Finite quotient": abstract part only.** Proved: `S/~P` is finite, `⟦P⟧` is
   constant on each cell, there are at most `|V|^n` cells, and the cells correspond exactly to
   the achieved outcome vectors. Not formalised: the per-component bound
   `∏ min(|D_i|, n_i + 1) · ∏ 2^(m_ℓ)` for the concrete language, and the claim that a witness
   for each cell is computable from `P`. Representatives of Lean quotients are not computable,
   and nothing in this development is about computability except Theorem `thm:undecidable`.
4. **Theorem "Combining-rule independence".** The hypothesis "the `g_i` are drawn from a
   finitely refining family" is replaced by "`V` is finite". Only the finite-image clause of
   Definition "Finite refinement" is used, and for guards with a finite outcome type it holds
   automatically (the manuscript's Lemma "The first clause of Definition `def:refining` is
   free"). The witness-procedure clause and "witnesses are computable" are not formalised. Of
   the results the theorem says "follow as before", the exact kill criterion and both
   corollaries are proved here for an arbitrary combining function. Theorem "Decidable
   equivalence" is not formalised.
5. **Corollary "Coverage decides the score".** `coverage_decides_score` asks only that `≈`
   refine the kernel of `⟦P⟧` and of every `⟦M⟧`. That is weaker than the manuscript's
   hypothesis that `≈` is the common refinement of `~P` and the `~M`. The family of mutants is
   indexed by an arbitrary type and may be infinite, where the manuscript takes a finite set.
   `coverage_decides_score_policies` is the manuscript's form, with `≈` the meet of `~P` and
   all `~M` (`commonRefinement`), which `commonRefinement_eq_ker` identifies with `~` of the
   concatenated guards. Finiteness of that refinement is `finite_commonRefinement`, and it
   needs finitely many mutants and finite outcome types. Computability of its witnesses is not
   formalised.
6. **Corollary "Semantic mutants".** Two hypotheses are added: `[Nontrivial D]`, meaning at
   least two decisions, for the only-if direction, and consistency of the suite with `P`,
   `T.Consistent P.sem`, for both directions. The manuscript states the corollary with
   neither, and the counterexamples show both are needed. The if direction
   (`semantic_mutants_sufficiency`) holds without `Nontrivial D`.
7. **Lemma "Which values existential guards achieve".** The general form is stated for finite
   sets `Finset α` of an arbitrary element type `α`; the manuscript has finite sets of
   strings. Guards are `Prop`-valued, and "`K` achieves `v`" is
   `∀ i, (∃ x ∈ K, m i x) ↔ v i = true`. The capability-pattern reading is proved only with a
   hypothesis the manuscript does not state: every wildcard stem is empty or ends with a
   separator `sep`, and some letter differs from `sep` (`achievable_iff_no_dominance`). Without
   it the reading is false (`dominance_reading_fails_without_separator`). The claim that both
   conditions are "decided by inspecting the guards" is not formalised as a decidability
   result, though `SynDominates` is the syntactic test it refers to.
8. **Lemma "Prefix patterns".** Stems are `List α` over any `α` with decidable equality, and the
   string ranges over all of `List α`. The bound is on `Set.ncard` of the set of achieved
   vectors, and the statement also asserts that set is finite, because `Set.ncard` of an
   infinite set is `0` and the bound alone would be vacuous.
9. **Theorem `thm:undecidable`.** Proved for the manuscript's own reduction: the policy `P_e`
   with the single guard "`e` halts on `0` within `len s` steps" against the always-deny
   policy, with `len : S → ℕ` surjective ("subjects of every length exist") and "halts within
   `k` steps" read as Mathlib's fuel-bounded evaluator `Nat.Partrec.Code.evaln k e 0`. The Lean
   theorem says the predicate `e ↦ (⟦P_e⟧ = ⟦deny⟧)` on programs `e : Nat.Partrec.Code` is not
   a `ComputablePred`. Not formalised: that each `g_e` is a computable function of the
   subject, and that a program for `g_e` is computable from `e`. The undecidable problem is
   posed over `e` rather than over a program text for the guard; the manuscript's argument
   that the two are inter-reducible is not mechanised.

Not formalised at all, beyond the parts noted above: Theorem "Tightness" (skipped by
instruction) and Lemma "Deciding occupancy is as good as constructing witnesses"; Lemma
"Scalar components"; Lemma "Set-valued components"; Theorem "Decidable equivalence"; Remark
"What an implementation must enumerate".

## Imprecisions in the manuscript

1. **Corollary "Semantic mutants" omits two hypotheses.** As stated ("`Σ` kills every
   non-equivalent mutant if and only if it covers `~P`"), it is false in two ways. With a
   single decision every semantic mutant equals `⟦P⟧`, so the left side holds vacuously while
   the empty suite covers nothing (`semantic_mutants_iff_fails_with_one_decision`). The
   necessity proof's step "pick `d ≠ ⟦P⟧(C)`" needs a second decision. Second, the suite must
   be consistent with `P`. The suite `{(true, true), (true, false)}` kills every mutant
   whatsoever without covering the other cell
   (`semantic_mutants_necessity_fails_without_consistency`), and an inconsistent pair on a
   one-cell quotient covers it yet lets a non-equivalent mutant survive
   (`semantic_mutants_sufficiency_fails_without_consistency`). The proof inherits consistency
   from Corollary "Coverage decides the score" without saying so. Suggested wording: "Let
   `|𝒟| ≥ 2` and let `Σ` be consistent with `P`. Then ...".
2. **Remark "Which clause of Definition `def:refining` fails" miscounts the cells.** It
   says each `g_e` "induces a partition of `Sub` into exactly two classes". When `e` does not
   halt on `0`, `g_e` is constantly `0` and there is exactly one class.
   `haltPolicy_card_cells_eq_one_iff` and `haltPolicy_card_cells_eq_two_iff` show the count is
   1 or 2 according as `e` does not or does halt, so which one it is is itself the halting
   question. The remark's next sentence, "whether that class is occupied at all is the halting
   question", is right and contradicts "exactly two". "At most two classes" is correct, and
   the remark's conclusion, that the finite-image clause holds, is unaffected.
3. **The capability-pattern reading of Lemma "Which values existential guards achieve" needs
   a hypothesis it does not state.** The lemma says that for capability patterns achievability
   reads "no pattern marked false dominates one marked true", for patterns that are "a literal
   or a literal followed by a final wildcard" (Definition "Guards and policies"). For arbitrary
   stems over a finite alphabet that is false. Over a two-letter alphabet `{a, b}`, take the
   wildcard `a*` marked true and, marked false, the literal `a` and the wildcards `aa*` and
   `ab*`. No false pattern dominates `a*`, yet every string matching `a*` matches one of them
   (`dominance_reading_fails_without_separator`, over the alphabet `Bool` with `a = true` and
   `b = false`). Over the full character set the same
   construction needs one false wildcard per character, so it is absurd in practice but still
   a counterexample to the statement. The proof uses the missing hypothesis in passing ("as
   `q_j` ends in a separator the tail does not contain"), and the implementation enforces it,
   since `validate_capability_pattern` in `src/trustweave/models.py` accepts only the namespace
   wildcard `.*`. With the hypothesis the reading is proved here
   (`achievable_iff_no_dominance`). Suggested fix: say in Definition "Guards and policies"
   that a wildcard pattern is a namespace wildcard, a literal ending in the separator followed
   by `*`, as the implementation requires.

Everything else in these sections that was formalised holds as stated: Theorem "Finite
quotient" (abstract part), Theorem "Combining-rule independence", Theorem "Exact kill
criterion", Corollary "Coverage decides the score" (in a slightly stronger form), the general
form and purpose-set reading of Lemma "Which values existential guards achieve", Lemma "Prefix
patterns are cheaper than they look", and Theorem `thm:undecidable`.

## Checks

- `lake build` exits 0 with no warnings from these sources.
- `grep -rn -E '\bsorry\b|\badmit\b' --include=*.lean` over the sources prints nothing, and
  there are no `axiom` declarations.
- `TrustweaveLean/Audit.lean` runs `#print axioms` for each of the 45 theorems stated
  in the sources. A cross-check outside Lean confirmed that list is exactly the set of
  `theorem` declarations. The build-time check covers every theorem in the namespace, 100 in
  all including the lemmas Lean generates.

## Axiom audit

Output of `lake env lean TrustweaveLean/Audit.lean`:

```
'TrustWeave.guardSim_iff' depends on axioms: [propext, Quot.sound]
'TrustWeave.Policy.sim_iff' depends on axioms: [propext, Quot.sound]
'TrustWeave.Policy.sem_eq_combine_outcome' does not depend on any axioms
'TrustWeave.Suite.covers_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.Policy.cellOutcome_mk' does not depend on any axioms
'TrustWeave.Policy.cellOutcome_injective' depends on axioms: [Quot.sound]
'TrustWeave.Policy.card_cells_eq_card_achieved' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.Policy.finite_cells' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.Policy.card_cells_le' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.Policy.sem_eq_of_sim' depends on axioms: [propext]
'TrustWeave.Policy.sim_le_ker_sem' depends on axioms: [propext]
'TrustWeave.Policy.cellSem_mk' depends on axioms: [propext]
'TrustWeave.Policy.sim_eq_of_guard_eq' depends on axioms: [propext]
'TrustWeave.combining_rule_independence' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.kill_criterion' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.exact_kill_criterion' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.coverage_decides_score' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.setoid_iInf_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.commonRefinement_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.commonRefinement_eq_ker' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.finite_commonRefinement' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.coverage_decides_score_policies' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.semantic_mutants_sufficiency_general' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.semantic_mutants_necessity_general' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.semantic_mutants_general' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.semantic_mutants_sufficiency' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.semantic_mutants' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.semantic_mutants_constant_on_cells' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.achievable_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.achieves_witness' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.achievable_iff_purpose' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.Pattern.dominates_iff_synDominates' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.achievable_iff_no_dominance' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.prefixOutcome_mem' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.prefix_patterns_card_le' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.exists_haltsWithin_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.haltsWithin_zero' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.haltPolicy_equiv_deny_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.policy_equivalence_undecidable' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.haltPolicy_card_cells_eq_one_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.haltPolicy_card_cells_eq_two_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.semantic_mutants_iff_fails_with_one_decision' depends on axioms: [propext, Classical.choice, Quot.sound]
'TrustWeave.semantic_mutants_necessity_fails_without_consistency' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
'TrustWeave.semantic_mutants_sufficiency_fails_without_consistency' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
'TrustWeave.dominance_reading_fails_without_separator' depends on axioms: [propext, Classical.choice, Quot.sound]
100 theorems in namespace TrustWeave (45 declared in the source) depend on no axioms beyond propext, Classical.choice and Quot.sound
```
