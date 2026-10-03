import TrustweaveLean.Kill
import TrustweaveLean.Patterns

/-!
# Counterexamples: hypotheses the paper's statements leave implicit

1. Corollary "Semantic mutants" is stated without hypotheses. Its forward direction needs at
   least two decisions, and both directions need the suite to be consistent with `P` (the
   paper inherits consistency from Corollary "Coverage decides the score" without restating
   it). Each counterexample below breaks exactly one of these hypotheses.
2. The capability-pattern reading of Lemma "Which values existential guards achieve" says a
   value is achieved iff no pattern marked false dominates one marked true. For final-wildcard
   patterns with arbitrary stems over a finite alphabet this is false. The paper's proof uses,
   without stating it in the lemma or in the language definition, that every wildcard stem
   ends with a namespace separator the witness tail avoids; with that hypothesis the reading
   holds (`achievable_iff_no_dominance` in `Patterns.lean`).
-/

namespace TrustWeave

/-! ## Corollary "Semantic mutants" -/

/-- With a single decision every mutant is equivalent to `P`, so "kills every non-equivalent
semantic mutant" holds vacuously, yet the empty suite (consistent with `P`) covers nothing. -/
theorem semantic_mutants_iff_fails_with_one_decision :
    ∃ (P : Policy Unit Unit Bool 0) (T : Suite Unit Unit), T.Consistent P.sem ∧
      (∀ μ : Quotient P.sim → Unit, (fun s => μ (Quotient.mk P.sim s)) ≠ P.sem →
        T.Kills fun s => μ (Quotient.mk P.sim s)) ∧
      ¬ T.Covers P.sim := by
  refine ⟨⟨fun i => i.elim0, fun _ => ()⟩, ∅, ?_, ?_, ?_⟩
  · intro s d h
    exact absurd h (Finset.notMem_empty _)
  · intro μ hμ
    exact absurd (funext fun _ => rfl) hμ
  · intro hcov
    obtain ⟨s, ⟨d, hd⟩, -⟩ := hcov (Quotient.mk _ ())
    exact Finset.notMem_empty _ hd

/-- Without consistency the forward direction fails: a suite with the two pairs `(true, true)`
and `(true, false)` kills every mutant whatsoever, but never witnesses the cell of `false`. -/
theorem semantic_mutants_necessity_fails_without_consistency :
    ∃ (P : Policy Bool Bool Bool 1) (T : Suite Bool Bool),
      (∀ μ : Quotient P.sim → Bool, (fun s => μ (Quotient.mk P.sim s)) ≠ P.sem →
        T.Kills fun s => μ (Quotient.mk P.sim s)) ∧
      ¬ T.Covers P.sim := by
  refine ⟨⟨fun _ s => s, fun _ => false⟩, {(true, true), (true, false)}, ?_, ?_⟩
  · intro μ _
    by_cases h : μ (Quotient.mk _ true) = true
    · exact ⟨true, false, by simp, by simp [h]⟩
    · exact ⟨true, true, by simp, h⟩
  · intro hcov
    obtain ⟨s, ⟨d, hd⟩, hc⟩ := hcov (Quotient.mk _ false)
    have hs : s = true := by
      simp only [Finset.mem_insert, Finset.mem_singleton, Prod.mk.injEq] at hd
      rcases hd with ⟨h, -⟩ | ⟨h, -⟩ <;> exact h
    subst hs
    have := (Policy.sim_iff _ true false).mp (Quotient.exact hc) 0
    exact Bool.noConfusion this

/-- Without consistency the backward direction fails too: on a one-cell quotient the suite
`{((), true)}` covers `~P`, but the mutant answering `true` everywhere differs from `P`
(which answers `false`) and survives it. -/
theorem semantic_mutants_sufficiency_fails_without_consistency :
    ∃ (P : Policy Unit Bool Bool 0) (T : Suite Unit Bool), T.Covers P.sim ∧
      ∃ μ : Quotient P.sim → Bool, (fun s => μ (Quotient.mk P.sim s)) ≠ P.sem ∧
        ¬ T.Kills fun s => μ (Quotient.mk P.sim s) := by
  refine ⟨⟨fun i => i.elim0, fun _ => false⟩, {((), true)}, ?_, fun _ => true, ?_, ?_⟩
  · intro c
    induction c using Quotient.ind with
    | _ s => exact ⟨(), ⟨true, Finset.mem_singleton_self _⟩, rfl⟩
  · intro h
    exact Bool.noConfusion (congrFun h ())
  · rintro ⟨s, d, hd, hk⟩
    simp only [Finset.mem_singleton, Prod.mk.injEq] at hd
    exact hk hd.2.symm

/-! ## The dominance reading of Lemma "Which values existential guards achieve" -/

/-- Over the two-letter alphabet `Bool`, take the wildcard `[t]*` marked true and, marked
false, the literal `[t]` and the wildcards `[t, t]*` and `[t, f]*`. No false pattern dominates
the true one, yet no finite set of strings achieves the value: every string matching `[t]*`
matches one of the three false patterns. Over any finite alphabet the same construction works
with one false wildcard per letter. The stems `[t, t]` and `[t, f]` do not end in a common
letter, so no separator satisfies the hypothesis of `achievable_iff_no_dominance`. -/
theorem dominance_reading_fails_without_separator :
    ∃ (q : Fin 4 → Pattern Bool) (v : Fin 4 → Bool),
      (∀ i j, v i = true → v j = false → ¬ (q j).Dominates (q i)) ∧
      ¬ ∃ K : Finset (List Bool), Achieves (fun i x => (q i).Matches x) K v := by
  refine ⟨![.wild [true], .lit [true], .wild [true, true], .wild [true, false]],
    ![true, false, false, false], ?_, ?_⟩
  · intro i j hi hj hdom
    fin_cases i <;> simp at hi
    fin_cases j <;> simp at hj
    · exact absurd (hdom [true, true] (List.prefix_append _ _)) (by simp [Pattern.Matches])
    · exact absurd (hdom [true] (List.prefix_refl _)) (by simp [Pattern.Matches])
    · exact absurd (hdom [true] (List.prefix_refl _)) (by simp [Pattern.Matches])
  · rintro hK
    obtain ⟨x, hx, hfalse⟩ := (achievable_iff _ _).mp hK 0 rfl
    obtain ⟨rest, rfl⟩ := hx
    cases rest with
    | nil => exact hfalse 1 rfl rfl
    | cons b rest =>
      cases b with
      | true => exact hfalse 2 rfl ⟨rest, rfl⟩
      | false => exact hfalse 3 rfl ⟨rest, rfl⟩

end TrustWeave
