import Mathlib

/-!
# Prefix patterns are cheaper than they look

Paper: Lemma "Prefix patterns are cheaper than they look".

For final-wildcard patterns with stems `q i : List α` (`i : Fin n`), guard `i` holds at a
string `s` when `q i` is a prefix of `s`. The prefixes of one string form a chain, and a chain
is determined by its longest member, so as `s` ranges over all lists at most `n + 1` of the
`2ⁿ` candidate outcome vectors are achieved.
-/

namespace TrustWeave

variable {α : Type*}

/-- The outcome vector of the prefix guards at the string `s`. -/
def prefixOutcome [DecidableEq α] {n : ℕ} (q : Fin n → List α) (s : List α) : Fin n → Bool :=
  fun i => decide (q i <+: s)

/-- Every achieved outcome vector is the all-`false` vector or the outcome vector of one of
the stems `q i` themselves. -/
theorem prefixOutcome_mem [DecidableEq α] {n : ℕ} (q : Fin n → List α) (s : List α) :
    prefixOutcome q s = (fun _ => false) ∨ ∃ i, prefixOutcome q s = prefixOutcome q (q i) := by
  classical
  by_cases hne : (Finset.univ.filter fun i => q i <+: s).Nonempty
  · right
    obtain ⟨i, hi, hmax⟩ := Finset.exists_max_image _ (fun i => (q i).length) hne
    have hi' : q i <+: s := (Finset.mem_filter.mp hi).2
    refine ⟨i, funext fun j => ?_⟩
    simp only [prefixOutcome, decide_eq_decide]
    constructor
    · intro hj
      exact List.prefix_of_prefix_length_le hj hi'
        (hmax j (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hj⟩))
    · intro hj
      exact hj.trans hi'
  · left
    funext j
    have hj : ¬ q j <+: s := fun h => hne ⟨j, Finset.mem_filter.mpr ⟨Finset.mem_univ _, h⟩⟩
    simp [prefixOutcome, hj]

/-- Paper, Lemma "Prefix patterns are cheaper than they look": as `s` ranges over all lists,
the outcome vector `fun i => decide (q i <+: s)` takes at most `n + 1` values. The set of
values is also stated to be finite, so the bound on `Set.ncard` is not vacuous. -/
theorem prefix_patterns_card_le [DecidableEq α] {n : ℕ} (q : Fin n → List α) :
    (Set.range fun s : List α => fun i => decide (q i <+: s)).Finite ∧
      (Set.range fun s : List α => fun i => decide (q i <+: s)).ncard ≤ n + 1 := by
  refine ⟨Set.toFinite _, ?_⟩
  let ψ : Option (Fin n) → (Fin n → Bool) := fun o =>
    match o with
    | none => fun _ => false
    | some i => prefixOutcome q (q i)
  have hsub : (Set.range fun s : List α => fun i => decide (q i <+: s)) ⊆ Set.range ψ := by
    rintro _ ⟨s, rfl⟩
    rcases prefixOutcome_mem q s with h | ⟨i, h⟩
    · exact ⟨none, h.symm⟩
    · exact ⟨some i, h.symm⟩
  calc (Set.range fun s : List α => fun i => decide (q i <+: s)).ncard
      ≤ (Set.range ψ).ncard := Set.ncard_le_ncard hsub (Set.toFinite _)
    _ ≤ (Set.univ : Set (Option (Fin n))).ncard := by
      rw [← Set.image_univ]
      exact Set.ncard_image_le (Set.toFinite _)
    _ = n + 1 := by
      rw [Set.ncard_univ, Nat.card_eq_fintype_card, Fintype.card_option, Fintype.card_fin]

end TrustWeave
