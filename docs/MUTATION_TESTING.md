# Focused Mutation-Testing Record

## Purpose and boundary

Mutation testing is used here as an additional test-suite diagnostic for a small deterministic core. It does **not** prove that TrustWeave is secure, does not cover every module, and is not a substitute for the ordinary test suite, policy fixtures, cross-platform compatibility jobs, static analysis, or human review.

The initial scope is intentionally limited to `src/trustweave/engine.py`. This module constructs the public Agent Security Bundle and applies deterministic declared-flow decisions. The scope is narrow so a reviewer can understand what was mutated, which tests were selected, and what a result does—and does not—support.

## Recorded run

| Field | Evidence |
| --- | --- |
| Date | 2026-08-14 |
| Tool | `mutmut 3.7.0` |
| Platform | Linux with fork support |
| Mutated source | `src/trustweave/engine.py` only |
| Test selection | Engine foundation, policy attributes, policy v1alpha2, and adversarial scenario suites; the unrelated repository-reality subprocess test is excluded. |
| Result | 384 generated mutants; 295 killed; 89 survived; 0 without a selected test; 0 timed out; 0 suspicious. |
| Focused score | 76.82% killed (`295 / 384`) |
| CI status | Informational and Linux-only; it is not a cross-platform release-blocking gate. |

This result improves test association for shared engine behavior, but it does **not** meet the roadmap target of at least 90% over the intended high-risk scope. The unaddressed survivors, broader high-risk module scope, and any final acceptance claim remain outstanding. The result must be re-run and updated whenever selected source, targeted tests, or mutation-tool configuration changes.

## Re-run procedure

Install the development dependencies on a POSIX environment with fork support, then run the following from a clean checkout.

```bash
python -m pip install -e ".[dev]"
rm -rf mutants
mutmut run
mutmut results
rm -rf mutants
```

The project configuration in `pyproject.toml` defines the source scope, local fixture copies, and test selection. The `mutants/` directory is generated output and must not be committed.

## Why this is not a mandatory compatibility job

The mutmut documentation states that its current execution model requires fork support and therefore needs WSL on Windows. TrustWeave supports Windows for its ordinary test suite, so making mutation analysis a required Windows gate would be misleading and brittle. This focused record is an explicit Linux-only diagnostic, not a portability claim.

## References

[1]: https://mutmut.readthedocs.io/ "mutmut documentation"
