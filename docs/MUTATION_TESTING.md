# High-Risk Mutation-Testing Record

## Purpose and boundary

Mutation testing is an additional diagnostic for TrustWeave's deterministic, high-risk core. It does **not** prove that TrustWeave is secure, does not cover every module, and is not a substitute for the ordinary test suite, policy fixtures, cross-platform compatibility jobs, static analysis, or human review.

The configured scope covers twelve high-risk modules: bundle and policy-decision behavior, public models, predicates, policy review, chain construction, canonical findings, risk lifecycle, evidence attestations, configuration handling, schema catalog access, SARIF rendering, and CI coordination. The scope remains narrower than the complete package; CLI parsing, report rendering, importers, and other adapters are not mutated by this diagnostic.

## Recorded run

| Field | Evidence |
| --- | --- |
| Date | 2026-08-18 |
| Tool | `mutmut 3.7.0` |
| Platform | Linux with fork support |
| Mutated source | `src/trustweave/engine.py`, `models.py`, `policy_predicates.py`, `policy_review.py`, `chain.py`, `findings.py`, `risk.py`, `evidence.py`, `config.py`, `schema_catalog.py`, `sarif.py`, and `commands/ci.py` |
| Fixture copy | Repository workflows, Docker assets, executable scripts, contract fixtures, schemas, examples, policies, scenarios, documentation, and public README assets are copied into the mutation workspace. |
| Test selection | `tests -k 'not repository_reality_check and not reality_check_contracts'`. The repository-reality subprocess test and its isolated-wheel contract test are excluded because instrumented source imports the mutation runtime, while those tests deliberately build a dependency-free isolated wheel. The ordinary release verification continues to execute both tests. |
| Result | 6,140 generated mutants; 6,044 killed; 96 survived; 0 without a selected test; 0 timed out; 0 suspicious. |
| High-risk scope score | 98.44% killed (`6,044 / 6,140`) |
| Hosted gate | `.github/workflows/mutation.yml` runs this Linux-only scope and enforces the 95% threshold, exact survivor-identifier parity, exact normalized survivor-diff/triage parity, no duplicate IDs, zero untriaged records, and zero `needs_regression` classifications. |

## Interpretation and survivor triage

The current twelve-module measurement reaches the owner-required **95% mutation threshold** for the measured high-risk scope. It is not a package-wide mutation-quality claim and does not establish that the package is secure.

Every survivor from this run has an individual source-level diff and an explicit classification in [`mutation-survivor-triage-v1.json`](mutation-survivor-triage-v1.json). The regenerated inventory records **96 classified survivors**, **0 untriaged survivors**, **96 equivalent mutations**, **0 defensive mutations**, and **0 mutations marked `needs_regression`**. Each equivalent record preserves a code-level proof that the changed expression is semantically redundant or unreachable under the strict local contracts.

Equivalent classifications are limited to code-proven semantic redundancies or unreachable control flow that cannot alter a successful public result, validation result, or reviewer-facing diagnostic. The inventory preserves the exact mutmut diff and rationale for every record; [`MUTATION_EQUIVALENCE_AUDIT.md`](MUTATION_EQUIVALENCE_AUDIT.md) records the security-focused review performed after the killed non-fail-closed approval-boundary mutant was reproduced. **This measurement satisfies the local zero-`needs_regression` and zero-untriaged requirements; final acceptance additionally requires the hosted parity gate to pass on the same commit SHA.**

The prior twelve-module measurements are superseded by this current configured run. Historical measurements must not be compared as though they represented the final high-risk scope result.

## Re-run procedure

Install the development dependencies on a POSIX environment with fork support, then run the following from a clean checkout.

```bash
python -m pip install -e ".[dev]"
rm -rf mutants .mutmut-cache
mutmut run
mutmut results
rm -rf mutants .mutmut-cache
```

The project configuration in `pyproject.toml` defines the twelve-module source scope, workspace fixture copies, and selected tests. The `mutants/` directory and `.mutmut-cache/` directory are generated output and must not be committed. The hosted Linux gate records `mutation-run.log`, `mutation-results.txt`, and `mutation-quality.json` as workflow evidence.

## Why this is Linux-only

The mutmut documentation states that its current execution model requires fork support and therefore needs WSL on Windows. TrustWeave supports Windows for its ordinary test suite, so making mutation analysis a required Windows gate would be misleading and brittle. The named hosted gate is Linux-only; it is a release-blocking quality check for the declared mutation scope, not a portability claim.

## References

[1]: https://mutmut.readthedocs.io/ "mutmut documentation"
