import TrustweaveLean.Quotient

/-!
# Killing mutants: the exact criterion, coverage, and semantic mutants

Paper: Theorem "Exact kill criterion", Corollary "Coverage decides the score", and
Corollary "Semantic mutants: coverage of the quotient is exactly right".

Each result is proved first for semantics given as plain functions `S → D` and an arbitrary
equivalence on `S`, and then stated in the paper's form over `Policy`. The mutants of the
paper's corollaries are policies too, but they need not share `P`'s guards, guard count or
outcome type, so a mutant policy here has its own `k` and `W`.
-/

namespace TrustWeave

variable {S D : Type*}

/-! ## Exact kill criterion -/

/-- Exact kill criterion, for semantics `p` (the policy) and `m` (the mutant). -/
theorem kill_criterion (p m : S → D) (T : Suite S D) (hT : T.Consistent p) :
    T.Kills m ↔ Delta p m ∩ T.witnessed ≠ ∅ := by
  rw [← Set.nonempty_iff_ne_empty]
  constructor
  · rintro ⟨s, d, hsd, hm⟩
    refine ⟨s, ?_, d, hsd⟩
    change p s ≠ m s
    rw [← hT s d hsd]
    exact fun h => hm h.symm
  · rintro ⟨s, hs, d, hsd⟩
    refine ⟨s, d, hsd, ?_⟩
    have hs' : p s ≠ m s := hs
    rw [hT s d hsd]
    exact fun h => hs' h.symm

/-- Paper, Theorem "Exact kill criterion": for a suite consistent with `P`, it kills `M` iff
`Δ(P, M) ∩ W(Σ) ≠ ∅`. The mutant `M` is any policy, with any number of guards and any
outcome type. -/
theorem exact_kill_criterion {V W : Type*} {n k : ℕ} (P : Policy S D V n)
    (M : Policy S D W k) (T : Suite S D) (hT : T.Consistent P.sem) :
    T.Kills M.sem ↔ Delta P.sem M.sem ∩ T.witnessed ≠ ∅ :=
  kill_criterion P.sem M.sem T hT

/-! ## Coverage decides the score -/

/-- Coverage decides the score, general form. Let `r` be any equivalence on subjects that
refines the kernel of the policy's semantics `p` and the kernel of every mutant semantics in
an arbitrary family `m`. If a suite is consistent with `p` and covers `r`, it kills every
mutant of the family that differs from `p`. -/
theorem coverage_decides_score {ι : Type*} (p : S → D) (m : ι → S → D) (r : Setoid S)
    (hp : r ≤ Setoid.ker p) (hm : ∀ j, r ≤ Setoid.ker (m j))
    (T : Suite S D) (hT : T.Consistent p) (hcov : T.Covers r) :
    ∀ j, m j ≠ p → T.Kills (m j) := by
  intro j hj
  obtain ⟨s, hs⟩ : ∃ s, m j s ≠ p s := Function.ne_iff.mp hj
  obtain ⟨s', ⟨d, hd⟩, hc⟩ := hcov (Quotient.mk r s)
  have hrel : r s' s := Quotient.exact hc
  have hp' : p s' = p s := Setoid.ker_def.mp (Setoid.le_def.mp hp hrel)
  have hm' : m j s' = m j s := Setoid.ker_def.mp (Setoid.le_def.mp (hm j) hrel)
  refine ⟨s', d, hd, ?_⟩
  rw [hT s' d hd, hm', hp']
  exact hs

/-- Membership in an indexed meet of equivalence relations. -/
theorem setoid_iInf_iff {ι : Type*} (r : ι → Setoid S) (x y : S) :
    (⨅ j, r j) x y ↔ ∀ j, r j x y := by
  rw [iInf, Setoid.sInf_def]
  simp

/-- The common refinement of `~P` and of `~M` for every mutant `M` of a family: the meet, in
the lattice of equivalence relations, of all those equivalences. -/
def commonRefinement {ι V : Type*} {n : ℕ} {W : ι → Type*} {k : ι → ℕ}
    (P : Policy S D V n) (M : ∀ j, Policy S D (W j) (k j)) : Setoid S :=
  P.sim ⊓ ⨅ j, (M j).sim

theorem commonRefinement_iff {ι V : Type*} {n : ℕ} {W : ι → Type*} {k : ι → ℕ}
    (P : Policy S D V n) (M : ∀ j, Policy S D (W j) (k j)) (s s' : S) :
    commonRefinement P M s s' ↔ P.sim s s' ∧ ∀ j, (M j).sim s s' := by
  rw [commonRefinement, Setoid.inf_iff_and, setoid_iInf_iff]

/-- The common refinement is the kernel of the joint guard-outcome map of `P` and all the
mutants, that is, `~` of the concatenation of all their guards. -/
theorem commonRefinement_eq_ker {ι V : Type*} {n : ℕ} {W : ι → Type*} {k : ι → ℕ}
    (P : Policy S D V n) (M : ∀ j, Policy S D (W j) (k j)) :
    commonRefinement P M = Setoid.ker fun s => (P.outcome s, fun j => (M j).outcome s) := by
  ext s s'
  simp only [commonRefinement_iff, Setoid.ker_def, Prod.mk.injEq, funext_iff, Policy.sim_iff,
    Policy.outcome]

/-- The common refinement of finitely many policies with finite outcome types has finitely
many classes. -/
theorem finite_commonRefinement {ι V : Type*} {n : ℕ} {W : ι → Type*} {k : ι → ℕ}
    [Finite ι] [Finite V] [∀ j, Finite (W j)]
    (P : Policy S D V n) (M : ∀ j, Policy S D (W j) (k j)) :
    Finite (Quotient (commonRefinement P M)) := by
  rw [commonRefinement_eq_ker]
  exact Finite.of_equiv _ (Setoid.quotientKerEquivRange _).symm

/-- Paper, Corollary "Coverage decides the score": let `≈` be the common refinement of `~P`
and the `~M` of every mutant in a family. A suite consistent with `P` that covers `≈` kills
every mutant `M` of the family with `⟦M⟧ ≠ ⟦P⟧`, whatever produced the family. The family
may be infinite; finiteness is needed only for `finite_commonRefinement`. -/
theorem coverage_decides_score_policies {ι V : Type*} {n : ℕ} {W : ι → Type*} {k : ι → ℕ}
    (P : Policy S D V n) (M : ∀ j, Policy S D (W j) (k j)) (T : Suite S D)
    (hT : T.Consistent P.sem) (hcov : T.Covers (commonRefinement P M)) :
    ∀ j, (M j).sem ≠ P.sem → T.Kills (M j).sem := by
  refine coverage_decides_score P.sem (fun j => (M j).sem) (commonRefinement P M) ?_ ?_ T hT hcov
  · exact le_trans inf_le_left P.sim_le_ker_sem
  · intro j
    exact le_trans (le_trans inf_le_right (iInf_le _ j)) (M j).sim_le_ker_sem

/-! ## Semantic mutants -/

/-- Semantic mutants, sufficiency, general form: if `r` refines the kernel of `p` and a suite
consistent with `p` covers `r`, it kills every function on `r`-classes whose semantics
differs from `p`. -/
theorem semantic_mutants_sufficiency_general (p : S → D) (r : Setoid S)
    (hp : r ≤ Setoid.ker p) (T : Suite S D) (hT : T.Consistent p) (hcov : T.Covers r) :
    ∀ μ : Quotient r → D, (fun s => μ (Quotient.mk r s)) ≠ p →
      T.Kills fun s => μ (Quotient.mk r s) := by
  refine coverage_decides_score p (fun μ : Quotient r → D => fun s => μ (Quotient.mk r s)) r
    hp ?_ T hT hcov
  intro μ
  exact Setoid.le_def.mpr fun h => Setoid.ker_def.mpr (congrArg μ (Quotient.sound h))

/-- Semantic mutants, necessity, general form. It needs two distinct decisions. -/
theorem semantic_mutants_necessity_general [Nontrivial D] (p : S → D) (r : Setoid S)
    (hp : r ≤ Setoid.ker p) (T : Suite S D) (hT : T.Consistent p)
    (hkill : ∀ μ : Quotient r → D, (fun s => μ (Quotient.mk r s)) ≠ p →
      T.Kills fun s => μ (Quotient.mk r s)) :
    T.Covers r := by
  classical
  by_contra hcov
  simp only [Suite.Covers, not_forall, not_exists, not_and] at hcov
  obtain ⟨c, hc⟩ := hcov
  obtain ⟨s₀, rfl⟩ := Quotient.exists_rep c
  obtain ⟨d, hd⟩ := exists_ne (p s₀)
  -- `p` on cells, then the mutant that answers `d` on the unwitnessed cell and agrees with
  -- `p` everywhere else.
  let pc : Quotient r → D :=
    Quotient.lift p fun _ _ h => Setoid.ker_def.mp (Setoid.le_def.mp hp h)
  let μ : Quotient r → D := fun c' => if c' = Quotient.mk r s₀ then d else pc c'
  have hne : (fun s => μ (Quotient.mk r s)) ≠ p := by
    intro h
    have h₀ := congrFun h s₀
    simp only [μ, ite_eq_left rfl] at h₀
    exact hd h₀
  obtain ⟨s, d', hsd, hk⟩ := hkill μ hne
  have hoff : Quotient.mk r s ≠ Quotient.mk r s₀ := hc s ⟨d', hsd⟩
  have hμ : μ (Quotient.mk r s) = p s := by
    simp only [μ, ite_eq_right hoff]
    rfl
  exact hk (hμ.trans (hT s d' hsd).symm)

/-- Semantic mutants, general form: for `p` constant on `r`-classes and a suite consistent
with `p`, the suite kills every non-equivalent function on `r`-classes iff it covers `r`. -/
theorem semantic_mutants_general [Nontrivial D] (p : S → D) (r : Setoid S)
    (hp : r ≤ Setoid.ker p) (T : Suite S D) (hT : T.Consistent p) :
    (∀ μ : Quotient r → D, (fun s => μ (Quotient.mk r s)) ≠ p →
      T.Kills fun s => μ (Quotient.mk r s)) ↔ T.Covers r :=
  ⟨semantic_mutants_necessity_general p r hp T hT,
    semantic_mutants_sufficiency_general p r hp T hT⟩

/-- Paper, Corollary "Semantic mutants", sufficiency: needs no hypothesis on `D`. -/
theorem semantic_mutants_sufficiency {V : Type*} {n : ℕ} (P : Policy S D V n) (T : Suite S D)
    (hT : T.Consistent P.sem) (hcov : T.Covers P.sim) :
    ∀ μ : Quotient P.sim → D, (fun s => μ (Quotient.mk P.sim s)) ≠ P.sem →
      T.Kills fun s => μ (Quotient.mk P.sim s) :=
  semantic_mutants_sufficiency_general P.sem P.sim P.sim_le_ker_sem T hT hcov

/-- Paper, Corollary "Semantic mutants: coverage of the quotient is exactly right". The
semantic mutants are all functions `μ : S/~P → D`, with semantics `s ↦ μ [s]`. For a suite
consistent with `P`, it kills every non-equivalent semantic mutant iff it covers `~P`.
`Nontrivial D` (at least two decisions) is needed for the forward direction, and is added
here; see `semantic_mutants_iff_fails_with_one_decision`. -/
theorem semantic_mutants {V : Type*} {n : ℕ} [Nontrivial D] (P : Policy S D V n)
    (T : Suite S D) (hT : T.Consistent P.sem) :
    (∀ μ : Quotient P.sim → D, (fun s => μ (Quotient.mk P.sim s)) ≠ P.sem →
      T.Kills fun s => μ (Quotient.mk P.sim s)) ↔ T.Covers P.sim :=
  semantic_mutants_general P.sem P.sim P.sim_le_ker_sem T hT

/-- The same corollary with the semantic mutants given as the functions `S → D` that are
constant on every cell of `~P`. -/
theorem semantic_mutants_constant_on_cells {V : Type*} {n : ℕ} [Nontrivial D]
    (P : Policy S D V n) (T : Suite S D) (hT : T.Consistent P.sem) :
    (∀ m : S → D, P.sim ≤ Setoid.ker m → m ≠ P.sem → T.Kills m) ↔ T.Covers P.sim := by
  rw [← semantic_mutants P T hT]
  constructor
  · intro h μ hμ
    refine h _ ?_ hμ
    exact Setoid.le_def.mpr fun hs => Setoid.ker_def.mpr (congrArg μ (Quotient.sound hs))
  · intro h m hm hne
    let μ : Quotient P.sim → D :=
      Quotient.lift m fun _ _ hs => Setoid.ker_def.mp (Setoid.le_def.mp hm hs)
    exact h μ hne

end TrustWeave
