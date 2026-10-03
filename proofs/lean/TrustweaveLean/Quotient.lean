import TrustweaveLean.Basic

/-!
# The finite quotient, for every combining function

Paper: Theorem "Finite quotient" (its abstract part: the quotient is finite and `⟦P⟧` is
constant on each cell) and Theorem "Combining-rule independence" (at most `|V|ⁿ` cells, for
an arbitrary combining function `c : Vⁿ → D`).

`~P` is the kernel of the guard-outcome map `s ↦ (g₁ s, …, gₙ s)`, so the cells inject into
`Fin n → V`; that one injection gives finiteness and the bound. The semantics consults only
the outcome vector, so it is constant on cells. The combining function appears nowhere in
`~P`: two policies with the same guards have the same quotient whatever they combine with.
-/

namespace TrustWeave

variable {S D V : Type*} {n : ℕ}

namespace Policy

/-- A cell's guard-outcome vector: the outcome map, descended to the quotient. -/
def cellOutcome (P : Policy S D V n) : Quotient P.sim → (Fin n → V) :=
  Quotient.lift P.outcome fun _ _ h => h

theorem cellOutcome_mk (P : Policy S D V n) (s : S) :
    P.cellOutcome (Quotient.mk P.sim s) = P.outcome s :=
  rfl

/-- Distinct cells have distinct outcome vectors. -/
theorem cellOutcome_injective (P : Policy S D V n) : Function.Injective P.cellOutcome := by
  intro a b h
  induction a using Quotient.ind with
  | _ s =>
    induction b using Quotient.ind with
    | _ s' => exact Quotient.sound h

/-- The cells are in bijection with the outcome vectors that some subject achieves. -/
noncomputable def cellsEquivAchieved (P : Policy S D V n) :
    Quotient P.sim ≃ Set.range P.outcome :=
  Setoid.quotientKerEquivRange P.outcome

/-- The number of cells is exactly the number of achieved outcome vectors (the bound
`|V|ⁿ` below counts candidate vectors, not achieved ones). -/
theorem card_cells_eq_card_achieved (P : Policy S D V n) :
    Nat.card (Quotient P.sim) = Nat.card (Set.range P.outcome) :=
  Nat.card_congr P.cellsEquivAchieved

/-- Paper, Theorem "Finite quotient" (abstract part): `S/~P` is finite. -/
theorem finite_cells [Finite V] (P : Policy S D V n) : Finite (Quotient P.sim) :=
  Finite.of_injective _ P.cellOutcome_injective

/-- Paper, Theorem "Combining-rule independence": at most `|V|ⁿ` cells. -/
theorem card_cells_le [Fintype V] (P : Policy S D V n) :
    Nat.card (Quotient P.sim) ≤ Fintype.card V ^ n := by
  calc Nat.card (Quotient P.sim)
      ≤ Nat.card (Fin n → V) := Nat.card_le_card_of_injective _ P.cellOutcome_injective
    _ = Fintype.card V ^ n := by
      rw [Nat.card_eq_fintype_card, Fintype.card_fun, Fintype.card_fin]

/-- Paper, Theorem "Finite quotient" (abstract part): `⟦P⟧` is constant on each cell. -/
theorem sem_eq_of_sim (P : Policy S D V n) {s s' : S} (h : P.sim s s') :
    P.sem s = P.sem s' := by
  have hv : (fun i => P.guard i s) = fun i => P.guard i s' := h
  simp only [sem, hv]

/-- `⟦P⟧` is constant on cells, phrased as a refinement: `~P` refines the kernel of `⟦P⟧`. -/
theorem sim_le_ker_sem (P : Policy S D V n) : P.sim ≤ Setoid.ker P.sem :=
  Setoid.le_def.mpr fun h => Setoid.ker_def.mpr (P.sem_eq_of_sim h)

/-- `⟦P⟧` as a function on cells. -/
def cellSem (P : Policy S D V n) : Quotient P.sim → D :=
  Quotient.lift P.sem fun _ _ h => P.sem_eq_of_sim h

/-- `⟦P⟧` factors through the quotient. -/
theorem cellSem_mk (P : Policy S D V n) (s : S) :
    P.cellSem (Quotient.mk P.sim s) = P.sem s :=
  rfl

/-- The quotient depends on the guards only: policies with the same guards have the same
`~P`, whatever their combining functions. -/
theorem sim_eq_of_guard_eq {P P' : Policy S D V n} (h : P.guard = P'.guard) :
    P.sim = P'.sim := by
  simp only [sim, h]

end Policy

/-- Paper, Theorem "Combining-rule independence" (the quotient part), bundled. Fix guards
`g : Fin n → S → V` with `V` finite and let `c : Vⁿ → D` be *any* combining function. Then
`~P` for `P = (g, c)` is the guard equivalence `guardSim g`, which does not mention `c`; the
quotient is finite with at most `|V|ⁿ` cells; and `⟦P⟧` is constant on every cell. -/
theorem combining_rule_independence [Fintype V] (g : Fin n → S → V) (c : (Fin n → V) → D) :
    (Policy.mk g c).sim = guardSim g ∧
    Finite (Quotient (Policy.mk g c).sim) ∧
    Nat.card (Quotient (Policy.mk g c).sim) ≤ Fintype.card V ^ n ∧
    ∀ s s' : S, (Policy.mk g c).sim s s' → (Policy.mk g c).sem s = (Policy.mk g c).sem s' :=
  ⟨rfl, Policy.finite_cells _, Policy.card_cells_le _, fun _ _ h => Policy.sem_eq_of_sim _ h⟩

end TrustWeave
