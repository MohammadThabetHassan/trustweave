import Mathlib

/-!
# Which values existential guards achieve

Paper: Lemma "Which values existential guards achieve", general form, and its purpose-set
reading.

A set-valued component carries guards `gᵢ(K) ≡ ∃ x ∈ K, mᵢ x`, one per `i : Fin k`, over
finite sets `K` of elements of an arbitrary type `α`. A value `v : Fin k → Bool` is achieved
by `K` when every guard's truth value at `K` is the one `v` prescribes. The lemma says which
`v` are achieved and gives the witness set `{xᵢ : vᵢ = true}`.

Not formalised here: the capability-pattern ("dominance") reading of the same lemma. See the
README for why that reading needs a hypothesis the paper's statement leaves out.
-/

namespace TrustWeave

variable {α : Type*} {k : ℕ}

/-- `K` achieves `v` for the existential guards `gᵢ(K) ≡ ∃ x ∈ K, m i x`: each guard holds
at `K` exactly when `v` marks it `true`. -/
def Achieves (m : Fin k → α → Prop) (K : Finset α) (v : Fin k → Bool) : Prop :=
  ∀ i, (∃ x ∈ K, m i x) ↔ v i = true

/-- Paper, Lemma "Which values existential guards achieve" (general form). A value `v` is
achieved by some finite set iff for every `i` with `v i = true` there is an element `x` with
`m i x` and `¬ m j x` for every `j` with `v j = false`. -/
theorem achievable_iff (m : Fin k → α → Prop) (v : Fin k → Bool) :
    (∃ K : Finset α, Achieves m K v) ↔
      ∀ i, v i = true → ∃ x, m i x ∧ ∀ j, v j = false → ¬ m j x := by
  constructor
  · rintro ⟨K, hK⟩ i hi
    obtain ⟨x, hxK, hx⟩ := (hK i).mpr hi
    refine ⟨x, hx, fun j hj hmj => ?_⟩
    have hvj : v j = true := (hK j).mp ⟨x, hxK, hmj⟩
    rw [hj] at hvj
    exact Bool.false_ne_true hvj
  · intro h
    classical
    choose f hf using h
    refine ⟨Finset.univ.image fun i : {i // v i = true} => f i.1 i.2, fun i => ?_⟩
    constructor
    · rintro ⟨x, hx, hmx⟩
      obtain ⟨⟨j, hj⟩, -, rfl⟩ := Finset.mem_image.mp hx
      by_contra hvi
      exact (hf j hj).2 i (Bool.eq_false_iff.mpr hvi) hmx
    · intro hvi
      exact ⟨f i hvi, Finset.mem_image.mpr ⟨⟨i, hvi⟩, Finset.mem_univ _, rfl⟩, (hf i hvi).1⟩

/-- The witness of the lemma: given, for each `i` marked `true`, an element `x i` with
`m i (x i)` that falsifies every guard marked `false`, the set `{x i : v i = true}` achieves
`v`. -/
theorem achieves_witness [DecidableEq α] (m : Fin k → α → Prop) (v : Fin k → Bool)
    (x : Fin k → α) (hx : ∀ i, v i = true → m i (x i) ∧ ∀ j, v j = false → ¬ m j (x i)) :
    Achieves m ((Finset.univ.filter fun i => v i = true).image x) v := by
  intro i
  constructor
  · rintro ⟨y, hy, hmy⟩
    obtain ⟨j, hj, rfl⟩ := Finset.mem_image.mp hy
    have hj' : v j = true := (Finset.mem_filter.mp hj).2
    by_contra hvi
    exact (hx j hj').2 i (Bool.eq_false_iff.mpr hvi) hmy
  · intro hvi
    exact ⟨x i, Finset.mem_image.mpr ⟨i, Finset.mem_filter.mpr ⟨Finset.mem_univ _, hvi⟩, rfl⟩,
      (hx i hvi).1⟩

/-- Paper, Lemma "Which values existential guards achieve", purpose-set reading. For guards
`G ∩ R ℓ ≠ ∅` on finite sets `G`, a value `v` is achieved iff no `R ℓ` marked `true` is
contained in the union of the `R j` marked `false`. -/
theorem achievable_iff_purpose (R : Fin k → Set α) (v : Fin k → Bool) :
    (∃ G : Finset α, ∀ l, ((↑G ∩ R l).Nonempty ↔ v l = true)) ↔
      ∀ l, v l = true → ¬ R l ⊆ ⋃ j ∈ {j | v j = false}, R j := by
  have key := achievable_iff (fun l x => x ∈ R l) v
  simp only [Achieves] at key
  have hG : ∀ G : Finset α, (∀ l, ((↑G ∩ R l).Nonempty ↔ v l = true)) ↔
      ∀ l, ((∃ x ∈ G, x ∈ R l) ↔ v l = true) := by
    intro G
    simp only [Set.Nonempty, Set.mem_inter_iff, Finset.mem_coe]
  simp only [hG, key]
  refine forall_congr' fun l => imp_congr_right fun _ => ?_
  simp only [Set.subset_def, Set.mem_iUnion, Set.mem_ofPred_eq, exists_prop, not_forall,
    not_exists, not_and]

end TrustWeave
