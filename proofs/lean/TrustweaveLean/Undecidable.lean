import TrustweaveLean.Quotient

/-!
# Where the fragment ends: equivalence with a step-bounded halting guard is undecidable

Paper: Theorem "undecidable" (section "Where the fragment ends").

Subjects form any type `S` with a length `len : S → ℕ` that takes every value ("subjects of
every length exist"). For a program `e` (a `Nat.Partrec.Code`), the guard `g_e` reports
whether `e` halts on input `0` within `len s` steps. "Within `k` steps" is Mathlib's
fuel-bounded evaluator `Nat.Partrec.Code.evaln k e 0`, which is total, and which returns a
value for some `k` exactly when `e` halts on `0` (`evaln_complete`, `evaln_sound`).

`P_e` has the single guard `g_e` and decides `allow` when it holds and `deny` otherwise; the
always-deny policy has no guards. `P_e` is equivalent to always-deny iff `e` does not halt on
`0`, so the predicate `e ↦ (⟦P_e⟧ = ⟦deny⟧)` is not computable: a decision procedure, uniform
in `e`, would decide the halting problem (`ComputablePred.halting_problem`).
-/

namespace TrustWeave

open Nat.Partrec

variable {S D : Type*}

/-- `e` halts on input `0` within `k` steps, read off Mathlib's fuel-bounded evaluator. -/
def haltsWithin (e : Code) (k : ℕ) : Bool :=
  (Code.evaln k e 0).isSome

/-- `e` halts on `0` within some number of steps iff it halts on `0`. -/
theorem exists_haltsWithin_iff (e : Code) :
    (∃ k, haltsWithin e k = true) ↔ (e.eval 0).Dom := by
  simp only [haltsWithin, Option.isSome_iff_exists, Part.dom_iff_mem]
  constructor
  · rintro ⟨k, x, hx⟩
    exact ⟨x, Code.evaln_sound hx⟩
  · rintro ⟨x, hx⟩
    obtain ⟨k, hk⟩ := Code.evaln_complete.mp hx
    exact ⟨k, x, hk⟩

/-- With zero steps nothing halts. -/
theorem haltsWithin_zero (e : Code) : haltsWithin e 0 = false := by
  rw [haltsWithin, Bool.eq_false_iff]
  intro h
  obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp h
  exact absurd (Code.evaln_bound hx) (Nat.not_lt_zero 0)

/-- `P_e`: one guard, "`e` halts on `0` within `len s` steps"; decision `allow` when the guard
holds and `deny` otherwise. -/
def haltPolicy (len : S → ℕ) (allow deny : D) (e : Code) : Policy S D Bool 1 where
  guard := fun _ s => haltsWithin e (len s)
  combine := fun v => if v 0 = true then allow else deny

/-- The policy with no guards that decides `deny` everywhere. -/
def denyPolicy (deny : D) : Policy S D Bool 0 where
  guard := fun i => i.elim0
  combine := fun _ => deny

/-- `P_e` is equivalent to always-deny iff `e` does not halt on `0`. -/
theorem haltPolicy_equiv_deny_iff (len : S → ℕ) (hlen : Function.Surjective len)
    {allow deny : D} (hne : allow ≠ deny) (e : Code) :
    (haltPolicy len allow deny e).sem = (denyPolicy deny).sem ↔ ¬ (e.eval 0).Dom := by
  rw [← exists_haltsWithin_iff, funext_iff]
  simp only [Policy.sem, haltPolicy, denyPolicy]
  constructor
  · rintro h ⟨k, hk⟩
    obtain ⟨s, rfl⟩ := hlen k
    have hs := h s
    rw [hk, ite_eq_left rfl] at hs
    exact hne hs
  · intro h s
    have hs : haltsWithin e (len s) = false :=
      Bool.eq_false_iff.mpr fun hs => h ⟨len s, hs⟩
    rw [hs]
    rfl

/-- Paper, Theorem "undecidable": there is no computable decision procedure, uniform in the
program `e`, for whether the policy whose single guard is "`e` halts on `0` within `|s|`
steps" is equivalent to the always-deny policy. -/
theorem policy_equivalence_undecidable (len : S → ℕ) (hlen : Function.Surjective len)
    {allow deny : D} (hne : allow ≠ deny) :
    ¬ ComputablePred fun e : Code =>
      (haltPolicy len allow deny e).sem = (denyPolicy deny).sem := by
  intro hc
  have hfun : (fun e : Code => (haltPolicy len allow deny e).sem = (denyPolicy deny).sem) =
      fun e => ¬ (e.eval 0).Dom :=
    funext fun e => propext (haltPolicy_equiv_deny_iff len hlen hne e)
  rw [hfun] at hc
  have hhalt : ComputablePred fun e : Code => (e.eval 0).Dom := by
    have h2 := hc.not
    simp only [not_not] at h2
    exact h2
  exact ComputablePred.halting_problem 0 hhalt

/-- How many cells `~P_e` has. A subject of length `0` makes the guard false, so the quotient
is never empty, and it has a single cell exactly when `e` does not halt on `0`. -/
theorem haltPolicy_card_cells_eq_one_iff (len : S → ℕ) (hlen : Function.Surjective len)
    (allow deny : D) (e : Code) :
    Nat.card (Quotient (haltPolicy len allow deny e).sim) = 1 ↔ ¬ (e.eval 0).Dom := by
  rw [Nat.card_eq_one_iff_unique, ← exists_haltsWithin_iff]
  obtain ⟨s₀, hs₀⟩ := hlen 0
  constructor
  · rintro ⟨hsub, -⟩ ⟨k, hk⟩
    obtain ⟨s₁, rfl⟩ := hlen k
    have hrel := Quotient.exact (hsub.elim (Quotient.mk _ s₀) (Quotient.mk _ s₁))
    have h0 := (Policy.sim_iff _ s₀ s₁).mp hrel 0
    simp only [haltPolicy, hs₀, haltsWithin_zero, hk] at h0
    exact Bool.false_ne_true h0
  · intro h
    have hall : ∀ s, haltsWithin e (len s) = false :=
      fun s => Bool.eq_false_iff.mpr fun hs => h ⟨len s, hs⟩
    refine ⟨⟨fun a b => ?_⟩, ⟨Quotient.mk _ s₀⟩⟩
    induction a using Quotient.ind with
    | _ s =>
      induction b using Quotient.ind with
      | _ s' =>
        refine Quotient.sound ((Policy.sim_iff _ s s').mpr fun i => ?_)
        simp only [haltPolicy, hall]

/-- When `e` halts on `0`, `~P_e` has exactly two cells; when it does not, exactly one
(`haltPolicy_card_cells_eq_one_iff`). Which case holds is the halting question. -/
theorem haltPolicy_card_cells_eq_two_iff (len : S → ℕ) (hlen : Function.Surjective len)
    (allow deny : D) (e : Code) :
    Nat.card (Quotient (haltPolicy len allow deny e).sim) = 2 ↔ (e.eval 0).Dom := by
  have hle := (haltPolicy len allow deny e).card_cells_le
  rw [Fintype.card_bool, pow_one] at hle
  have hfin := (haltPolicy len allow deny e).finite_cells
  obtain ⟨s₀, -⟩ := hlen 0
  have hpos : 0 < Nat.card (Quotient (haltPolicy len allow deny e).sim) :=
    Nat.card_pos_iff.mpr ⟨⟨Quotient.mk _ s₀⟩, hfin⟩
  have h1 := haltPolicy_card_cells_eq_one_iff len hlen allow deny e
  constructor
  · intro h2
    by_contra hdom
    have := h1.mpr hdom
    omega
  · intro hdom
    have hne1 : Nat.card (Quotient (haltPolicy len allow deny e).sim) ≠ 1 :=
      fun h => h1.mp h hdom
    omega

end TrustWeave
