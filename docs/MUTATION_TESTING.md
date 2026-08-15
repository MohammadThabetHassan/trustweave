# High-Risk Mutation-Testing Record

## Purpose and boundary

Mutation testing is an additional diagnostic for TrustWeave's deterministic, high-risk core. It does **not** prove that TrustWeave is secure, does not cover every module, and is not a substitute for the ordinary test suite, policy fixtures, cross-platform compatibility jobs, static analysis, or human review.

The configured scope covers twelve high-risk modules: bundle and policy-decision behavior, public models, predicates, policy review, chain construction, canonical findings, risk lifecycle, evidence attestations, configuration handling, schema catalog access, SARIF rendering, and CI coordination. The scope remains narrower than the complete package; CLI parsing, report rendering, importers, and other adapters are not mutated by this diagnostic.

## Recorded run

| Field | Evidence |
| --- | --- |
| Date | 2026-08-15 |
| Tool | `mutmut 3.7.0` |
| Platform | Linux with fork support |
| Mutated source | `src/trustweave/engine.py`, `models.py`, `policy_predicates.py`, `policy_review.py`, `chain.py`, `findings.py`, `risk.py`, `evidence.py`, `config.py`, `schema_catalog.py`, `sarif.py`, and `commands/ci.py` |
| Fixture copy | Repository workflows, Docker assets, executable scripts, contract fixtures, schemas, examples, policies, scenarios, documentation, and public README assets are copied into the mutation workspace. |
| Test selection | `tests -k 'not repository_reality_check and not reality_check_contracts'`. The repository-reality subprocess test and its isolated-wheel contract test are excluded because instrumented source imports the mutation runtime, while those tests deliberately build a dependency-free isolated wheel. The ordinary release verification continues to execute both tests. |
| Result | 6,063 generated mutants; 4,787 killed; 1,276 survived; 0 without a selected test; 0 timed out; 0 suspicious. |
| High-risk scope score | 78.95% killed (`4,787 / 6,063`) |
| CI status | Informational and Linux-only; it is not a cross-platform release-blocking gate. |

## Interpretation and remaining work

The expanded twelve-module run is a reproducible, honest measurement but **does not meet a 90% mutation threshold** for the measured high-risk scope. It therefore does not establish the audit's full 9.8 acceptance gate or a package-wide mutation-quality claim. The 1,276 surviving mutants remain untriaged and require maintainer classification as equivalent changes or additional behavioral assertions; none have been silently suppressed.

The prior four-module measurement is superseded by this broader configured run. It recorded 2,614 generated mutants, 2,128 killed, and 486 survivors, for 81.41%; it must not be compared as though it represented the twelve-module scope.

## Re-run procedure

Install the development dependencies on a POSIX environment with fork support, then run the following from a clean checkout.

```bash
python -m pip install -e ".[dev]"
rm -rf mutants .mutmut-cache
mutmut run
mutmut results
rm -rf mutants .mutmut-cache
```

The project configuration in `pyproject.toml` defines the twelve-module source scope, workspace fixture copies, and selected tests. The `mutants/` directory and `.mutmut-cache/` directory are generated output and must not be committed.

## Why this is not a mandatory compatibility job

The mutmut documentation states that its current execution model requires fork support and therefore needs WSL on Windows. TrustWeave supports Windows for its ordinary test suite, so making mutation analysis a required Windows gate would be misleading and brittle. This record is an explicit Linux-only diagnostic, not a portability claim.

## References

[1]: https://mutmut.readthedocs.io/ "mutmut documentation"
