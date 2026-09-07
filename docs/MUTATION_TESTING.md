# High-Risk Mutation-Testing Record

## Purpose and boundary

Mutation testing is an additional diagnostic for TrustWeave's deterministic, high-risk core. It does **not** prove that TrustWeave is secure, does not cover every module, and is not a substitute for the ordinary test suite, policy fixtures, cross-platform compatibility jobs, static analysis, or human review.

The configured scope covers fourteen high-risk modules: deterministic engine and public models; predicates and policy review; chain construction and canonical findings; risk lifecycle, evidence attestations, configuration, schema catalog access, SARIF rendering, and CI coordination; plus the dedicated `bundle_policy.py` generated-null normalization and `policy_weakening.py` classifier that supply the corrective bundle/diff behavior. The scope remains narrower than the complete package; CLI parsing, report rendering, importers, and other adapters are not mutated by this diagnostic.

## The discovery layer in the gate

The gate covered fourteen modules and none of the three implementing `trustweave discover`.
Measured before any work: **2,073 mutants, 1,474 killed, 581 survived — 71.7%**, against 96%
line-and-branch coverage on the same code. The whole run takes 160 seconds at ~55
mutations/second, so runtime was never the obstacle. Two of the three are now gated.

| Module | Before | Now | In the gate |
|---|---|---|---|
| `code_discovery.py` | 53.4% | **97.5%** | yes |
| `code_sources.py` | 69.8% | **88.4%** | yes, carried by the aggregate |
| `code_analysis.py` | ~70% | ~70% | not yet |

### What moved `code_discovery.py` from 53% to 97%

Most of its survivors renamed a dictionary key — `location` to `LOCATION`,
`schema_version` to `SCHEMA_VERSION` — and passed. The artifact is a published contract
with a JSON schema shipped in the package, and **no test validated an emitted artifact
against it**. Doing so, in both the with-manifest and without-manifest shapes, killed those
at a stroke, because the schema sets `additionalProperties: false` and lists required keys.
Three further tests prove the schema actually rejects a renamed section, so the validation
is load-bearing rather than decorative.

The rest were the fields a reviewer acts on and the arithmetic behind them: every rule's id,
severity, subject, location and properties; which rule fires for which reason set; the
coverage basis-point floor division; the rename heuristic at its similarity cutoff; the
summary counts partitioning the tool list; and the draft's review instructions, asserted as
one exact list because that text is what stops a draft being used as a declaration.

### Why `code_sources.py` stops at 88.4%

Its fifteen remaining survivors cannot be killed:

| Count | Survivor | Why |
|---|---|---|
| 8 | the `path_escapes_analyzed_root` branch | unreachable: the walk already skips symlinked files and prunes symlinked directories, so `os.walk` never yields a candidate whose resolved path escapes the resolved root |
| 5 | `followlinks=None` / omitted / `True`, `encoding="UTF-8"` / `None` | equivalent: `None` is falsy, the parameter defaults to `False`, pruning removes symlinked directories whatever `followlinks` says, and both encodings name one codec |
| 2 | `InputOutputError` message on a stat or read failure | environment-specific, already marked `# pragma: no cover` |

Passing 95% on that module alone would mean deleting a defence-in-depth check or contriving
a test for a state the code cannot reach. It is gated anyway, because the gate scores the
aggregate and the module's shortfall is small against the total.

### `code_analysis.py` is not gated yet

1,459 lines, ~1,100 mutants, ~334 surviving. It is the largest module in the package and
raising it is the same kind of work done above, at roughly three times the size. Recorded
here rather than left as an unexplained absence.

## Recorded run

| Field | Evidence |
| --- | --- |
| Date | 2026-08-20 |
| Tool | `mutmut 3.7.0` |
| Platform | Linux with fork support |
| Mutated source | `src/trustweave/engine.py`, `models.py`, `policy_predicates.py`, `policy_review.py`, `chain.py`, `findings.py`, `risk.py`, `evidence.py`, `config.py`, `schema_catalog.py`, `sarif.py`, `commands/ci.py`, `bundle_policy.py`, and `policy_weakening.py` |
| Fixture copy | Repository workflows, Docker assets, executable scripts, contract fixtures, schemas, examples, policies, scenarios, documentation, and public README assets are copied into the mutation workspace. |
| Test selection | `tests -k 'not repository_reality_check and not reality_check_contracts'`. The repository-reality subprocess test and its isolated-wheel contract test are excluded because instrumented source imports the mutation runtime, while those tests deliberately build a dependency-free isolated wheel. The ordinary release verification continues to execute both tests. |
| Result | 6,691 generated mutants; 6,565 killed; 126 survived; 0 without a selected test; 0 timed out; 0 suspicious. |
| High-risk scope score | 98.12% killed (`6,565 / 6,691`) |
| Hosted gate | `.github/workflows/mutation.yml` runs this Linux-only scope and enforces the 95% threshold, exact survivor-identifier parity, exact normalized survivor-diff/triage parity, no duplicate IDs, zero untriaged records, and zero `needs_regression` classifications. |

## Interpretation and survivor triage

The current fourteen-module measurement reaches the owner-required **95% mutation threshold** for the measured high-risk scope. It is not a package-wide mutation-quality claim and does not establish that the package is secure.

Every survivor from this run has an individual source-level diff and an explicit classification in [`mutation-survivor-triage-v1.json`](mutation-survivor-triage-v1.json). The regenerated inventory records **126 classified survivors**, **0 untriaged survivors**, **126 equivalent mutations**, **0 defensive mutations**, and **0 mutations marked `needs_regression`**. The 19 `policy_weakening.py` survivors are limited to unreachable strict-parser defaults, unique-position ordering forms, and normalization predicates; the inventory preserves their exact diffs and code-level proofs. Each equivalent record preserves a code-level proof that the changed expression is semantically redundant or unreachable under the strict local contracts.

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

The project configuration in `pyproject.toml` defines the fourteen-module source scope, workspace fixture copies, and selected tests. The `mutants/` directory and `.mutmut-cache/` directory are generated output and must not be committed. The hosted Linux gate records `mutation-run.log`, `mutation-results.txt`, and `mutation-quality.json` as workflow evidence.

## Why this is Linux-only

The mutmut documentation states that its current execution model requires fork support and therefore needs WSL on Windows. TrustWeave supports Windows for its ordinary test suite, so making mutation analysis a required Windows gate would be misleading and brittle. The named hosted gate is Linux-only; it is a release-blocking quality check for the declared mutation scope, not a portability claim.

## References

[1]: https://mutmut.readthedocs.io/ "mutmut documentation"
