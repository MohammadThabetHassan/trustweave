import Mathlib

/-!
# The abstract policy setting

The objects of the paper's sections "The quotient, and what is exact within it" and
"The evaluation rule does not matter", in the general form of the theorem
"Combining-rule independence".

* Subjects form an arbitrary type `S` and decisions an arbitrary type `D`.
* A policy is `n` guards `g : Fin n → S → V`, each reporting a value in a type `V` of guard
  outcomes, together with a combining function `c : (Fin n → V) → D`. Its semantics is
  `⟦P⟧ s = c (fun i => g i s)`. Nothing about first-match evaluation is assumed: every result
  stated over `Policy` holds for every combining function.
* `s ~P s'` holds when every guard of `P` gives `s` and `s'` the same value.
* A suite is a finite set of `(subject, decision)` pairs.

The suite notions (`witnessed`, `Consistent`, `Covers`, `Kills`) and `Delta` take the policy
and the mutant as *functions* `S → D`, that is, through their semantics. A policy `P` enters
as `P.sem`, and a mutant may be any policy whatsoever, with its own number of guards and its
own outcome type, entering as its `sem`.
-/

namespace TrustWeave

/-- A policy over subjects `S` and decisions `D`: `n` guards, guard `i` reporting
`guard i s : V` at subject `s`, and a combining function on the vector of guard outcomes. -/
structure Policy (S D V : Type*) (n : ℕ) where
  /-- The guards `g₁, …, gₙ`. -/
  guard : Fin n → S → V
  /-- The combining function `c : Vⁿ → D`. -/
  combine : (Fin n → V) → D

variable {S D V : Type*} {n : ℕ}

/-- The equivalence a guard family induces on subjects: two subjects are related when every
guard gives them the same value. It is the kernel of the guard-outcome map, and it mentions
no combining function. -/
def guardSim (g : Fin n → S → V) : Setoid S :=
  Setoid.ker fun s i => g i s

theorem guardSim_iff (g : Fin n → S → V) (s s' : S) :
    guardSim g s s' ↔ ∀ i, g i s = g i s' := by
  rw [guardSim, Setoid.ker_def, funext_iff]

namespace Policy

/-- The guard-outcome vector `(g₁ s, …, gₙ s)` of a subject. -/
def outcome (P : Policy S D V n) (s : S) : Fin n → V :=
  fun i => P.guard i s

/-- The semantics `⟦P⟧ s = c (fun i => g i s)`. -/
def sem (P : Policy S D V n) (s : S) : D :=
  P.combine fun i => P.guard i s

/-- The policy-relative equivalence `~P`: `s ~P s'` iff `∀ i, g i s = g i s'`. Its classes
are the paper's *cells*, and `Quotient P.sim` is the paper's `S/~P`. -/
def sim (P : Policy S D V n) : Setoid S :=
  guardSim P.guard

theorem sim_iff (P : Policy S D V n) (s s' : S) :
    P.sim s s' ↔ ∀ i, P.guard i s = P.guard i s' :=
  guardSim_iff P.guard s s'

theorem sem_eq_combine_outcome (P : Policy S D V n) (s : S) :
    P.sem s = P.combine (P.outcome s) :=
  rfl

end Policy

/-- A suite: a finite set of `(subject, decision)` pairs. -/
abbrev Suite (S D : Type*) :=
  Finset (S × D)

namespace Suite

/-- `W(Σ) = {s | (s, d) ∈ Σ for some d}`, the subjects a suite witnesses. -/
def witnessed (T : Suite S D) : Set S :=
  {s | ∃ d, (s, d) ∈ T}

/-- A suite is consistent with a semantics `f` when `d = f s` for every pair `(s, d)`. -/
def Consistent (T : Suite S D) (f : S → D) : Prop :=
  ∀ s d, (s, d) ∈ T → d = f s

/-- A suite covers an equivalence `r` when `W(Σ)` meets every `r`-class: every class
contains the subject of some pair. -/
def Covers (T : Suite S D) (r : Setoid S) : Prop :=
  ∀ c : Quotient r, ∃ s ∈ T.witnessed, Quotient.mk r s = c

/-- A suite kills a mutant (given by its semantics `m`) when `m s ≠ d` for some pair. -/
def Kills (T : Suite S D) (m : S → D) : Prop :=
  ∃ s d, (s, d) ∈ T ∧ m s ≠ d

theorem covers_iff (T : Suite S D) (r : Setoid S) :
    T.Covers r ↔ ∀ s, ∃ s' ∈ T.witnessed, r s' s := by
  constructor
  · intro h s
    obtain ⟨s', hs', hc⟩ := h (Quotient.mk r s)
    exact ⟨s', hs', Quotient.exact hc⟩
  · intro h c
    induction c using Quotient.ind with
    | _ s =>
      obtain ⟨s', hs', hr⟩ := h s
      exact ⟨s', hs', Quotient.sound hr⟩

end Suite

/-- `Δ(P, M) = {s | ⟦P⟧ s ≠ ⟦M⟧ s}`, for semantics `p` and `m`. -/
def Delta (p m : S → D) : Set S :=
  {s | p s ≠ m s}

end TrustWeave
