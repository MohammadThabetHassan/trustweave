import TrustweaveLean.Achievable

/-!
# Capability patterns and dominance

Paper: Lemma "Which values existential guards achieve", capability-pattern reading.

A capability pattern is a literal or a stem followed by a final wildcard. Matching is the
paper's solver encoding: a literal as equality, a final-wildcard pattern as a prefix test on
its stem. `q` dominates `q'` when every string matching `q'` matches `q`.

The paper reads its general lemma, for capability patterns, as "a value is achieved iff no
pattern marked false dominates one marked true". That reading holds under the hypothesis the
paper's proof uses: every wildcard stem ends with a namespace separator `sep` (the
implementation only accepts `.*` wildcards), and the alphabet has a letter other than `sep`
to build the witness tail from. `achievable_iff_no_dominance` proves it under exactly that
hypothesis; `dominance_reading_fails_without_separator` (in `Counterexamples.lean`) shows it
fails without it.
-/

namespace TrustWeave

variable {α : Type*}

/-- A capability pattern: a literal, or a stem followed by a final wildcard. -/
inductive Pattern (α : Type*) where
  /-- A literal; it matches exactly itself. -/
  | lit : List α → Pattern α
  /-- A stem followed by a final wildcard; it matches every string the stem prefixes. -/
  | wild : List α → Pattern α

namespace Pattern

/-- Matching: a literal as equality, a final-wildcard pattern as a prefix test on its stem. -/
def Matches : Pattern α → List α → Prop
  | lit l, x => x = l
  | wild st, x => st <+: x

/-- `q` dominates `q'` when every string matching `q'` matches `q`. -/
def Dominates (q q' : Pattern α) : Prop :=
  ∀ x, q'.Matches x → q.Matches x

/-- The paper's syntactic description of dominance: a final wildcard with stem `st` dominates
every pattern whose literal or stem extends `st`, and a literal dominates only itself. -/
def SynDominates : Pattern α → Pattern α → Prop
  | wild st, lit l => st <+: l
  | wild st, wild st' => st <+: st'
  | lit l, lit l' => l = l'
  | lit _, wild _ => False

/-- The length of a pattern's literal or stem. -/
def len : Pattern α → ℕ
  | lit l => l.length
  | wild st => st.length

/-- Over a nonempty alphabet, dominance is exactly the paper's syntactic description. -/
theorem dominates_iff_synDominates [Nonempty α] (q q' : Pattern α) :
    q.Dominates q' ↔ q.SynDominates q' := by
  cases q with
  | lit l =>
    cases q' with
    | lit l' =>
      simp only [Dominates, Matches, SynDominates]
      constructor
      · intro h
        exact (h l' rfl).symm
      · rintro rfl x hx
        exact hx
    | wild st' =>
      simp only [Dominates, Matches, SynDominates, iff_false]
      intro h
      obtain ⟨a⟩ := ‹Nonempty α›
      have h1 : st' = l := h st' (List.prefix_refl _)
      have h2 : st' ++ [a] = l := h (st' ++ [a]) (List.prefix_append _ _)
      have h3 := congrArg List.length (h2.trans h1.symm)
      simp at h3
  | wild st =>
    cases q' with
    | lit l' =>
      simp only [Dominates, Matches, SynDominates]
      constructor
      · intro h
        exact h l' rfl
      · rintro h x rfl
        exact h
    | wild st' =>
      simp only [Dominates, Matches, SynDominates]
      constructor
      · intro h
        exact h st' (List.prefix_refl _)
      · intro h x hx
        exact h.trans hx

end Pattern

open Pattern in
/-- Paper, Lemma "Which values existential guards achieve", capability-pattern reading, under
the hypothesis its proof relies on: every wildcard stem is empty or ends with the separator
`sep`, and some letter `c` differs from `sep`. Then a value `v` is achieved by some finite set
of capabilities iff no pattern marked false dominates one marked true. -/
theorem achievable_iff_no_dominance (sep c : α) (hc : c ≠ sep) {k : ℕ}
    (q : Fin k → Pattern α)
    (hsep : ∀ j st, q j = wild st → st = [] ∨ ∃ pre, st = pre ++ [sep]) (v : Fin k → Bool) :
    (∃ K : Finset (List α), Achieves (fun i x => (q i).Matches x) K v) ↔
      ∀ i j, v i = true → v j = false → ¬ (q j).Dominates (q i) := by
  rw [achievable_iff]
  constructor
  · intro h i j hi hj hdom
    obtain ⟨x, hx, hfalse⟩ := h i hi
    exact hfalse j hj (hdom x hx)
  · intro h i hi
    -- A tail length beyond the length of every literal and stem of the policy.
    let N := (∑ j, (q j).len) + 1
    have hN : ∀ j, (q j).len < N := fun j =>
      Nat.lt_succ_of_le (Finset.single_le_sum (f := fun j => (q j).len)
        (fun _ _ => Nat.zero_le _) (Finset.mem_univ j))
    cases hqi : q i with
    | lit l =>
      -- The literal itself is matched only by the patterns that dominate it.
      refine ⟨l, ?_, fun j hj hm => h i j hi hj ?_⟩
      · simp only [Matches]
      · rw [hqi]
        intro y hy
        simp only [Matches] at hy
        subst hy
        exact hm
    | wild st =>
      -- The stem followed by a long tail of a non-separator letter.
      refine ⟨st ++ List.replicate N c, ?_, fun j hj hm => ?_⟩
      · simp only [Matches]
        exact List.prefix_append _ _
      · cases hqj : q j with
        | lit l' =>
          simp only [hqj, Matches] at hm
          have hl := hN j
          simp only [hqj, len] at hl
          have hlen := congrArg List.length hm
          simp only [List.length_append, List.length_replicate] at hlen
          omega
        | wild st' =>
          simp only [hqj, Matches] at hm
          by_cases hle : st'.length ≤ st.length
          · apply h i j hi hj
            rw [hqi, hqj]
            intro y hy
            simp only [Matches] at hy ⊢
            exact (List.prefix_of_prefix_length_le hm (List.prefix_append _ _) hle).trans hy
          · rcases hsep j st' hqj with rfl | ⟨pre, rfl⟩
            · simp at hle
            · have hpl : st.length ≤ pre.length := by
                simp only [List.length_append, List.length_cons, List.length_nil] at hle
                omega
              have hi1 : pre.length < (pre ++ [sep]).length := by simp
              have e1 := hm.getElem hi1
              rw [List.getElem_concat_length rfl, List.getElem_append_right hpl,
                List.getElem_replicate] at e1
              exact hc e1.symm

end TrustWeave
