# High-Risk Mutation-Testing Record

## Purpose and boundary

Mutation testing is an additional diagnostic for TrustWeave's deterministic, high-risk core. It does **not** prove that TrustWeave is secure, does not cover every module, and is not a substitute for the ordinary test suite, policy fixtures, cross-platform compatibility jobs, static analysis, or human review.

The configured scope covers the bundle decision engine, public model contracts, shared policy predicates, and risk-baseline lifecycle. These modules were selected because they construct canonical evidence, normalize declared inputs, decide policy coverage, and maintain stable review identity. The scope remains narrower than the complete package; adapters, command orchestration, schema catalog access, report rendering, importers, and other modules are not mutated by this diagnostic.

## Recorded run

| Field | Evidence |
| --- | --- |
| Date | 2026-08-14 |
| Tool | `mutmut 3.7.0` |
| Platform | Linux with fork support |
| Mutated source | `src/trustweave/engine.py`, `models.py`, `policy_predicates.py`, and `risk.py` |
| Test selection | Engine foundation and mutation contracts; policy attributes, v1alpha2, and review suites; adversarial scenarios; canonical findings; models contracts; risk management; and risk-schema suites. The unrelated repository-reality subprocess test is excluded. |
| Result | 2,339 generated mutants; 1,911 killed; 428 survived; 0 without a selected test; 0 timed out; 0 suspicious. |
| High-risk scope score | 81.70% killed (`1,911 / 2,339`) |
| CI status | Informational and Linux-only; it is not a cross-platform release-blocking gate. |

The earlier engine-only diagnostic was superseded by this broader configured run. It measured 387 mutants, killed 354, and left 33 survivors, for 91.47% within `engine.py`; that result must not be compared as though it represented the four-module scope.

## Interpretation and remaining work

The four-module result broadens evidence beyond the engine, but **does not meet a 90% mutation threshold** for the measured high-risk scope. It therefore does not establish a full 9.8 acceptance gate or a package-wide mutation-quality claim. The 428 surviving mutants require maintainer triage to distinguish equivalent changes from behavior that needs additional assertions. No survivor has been silently suppressed, and the measurement is retained as an honest release-review input rather than treated as a passing release control.

## Re-run procedure

Install the development dependencies on a POSIX environment with fork support, then run the following from a clean checkout.

```bash
python -m pip install -e ".[dev]"
rm -rf mutants .mutmut-cache
mutmut run
mutmut results
rm -rf mutants .mutmut-cache
```

The project configuration in `pyproject.toml` defines the four-module source scope, local fixture copies, and selected tests. The `mutants/` directory and `.mutmut-cache/` directory are generated output and must not be committed.

## Why this is not a mandatory compatibility job

The mutmut documentation states that its current execution model requires fork support and therefore needs WSL on Windows. TrustWeave supports Windows for its ordinary test suite, so making mutation analysis a required Windows gate would be misleading and brittle. This record is an explicit Linux-only diagnostic, not a portability claim.

## References

[1]: https://mutmut.readthedocs.io/ "mutmut documentation"
