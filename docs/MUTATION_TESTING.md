# High-Risk Mutation-Testing Record

## Purpose and boundary

Mutation testing is an additional diagnostic for TrustWeave's deterministic, high-risk core. It does **not** prove that TrustWeave is secure, does not cover every module, and is not a substitute for the ordinary test suite, policy fixtures, cross-platform compatibility jobs, static analysis, or human review.

The configured scope covers sixteen high-risk modules: deterministic engine and public models; predicates and policy review; chain construction and canonical findings; risk lifecycle, evidence attestations, configuration, schema catalog access, SARIF rendering, and CI coordination; plus the dedicated `bundle_policy.py` generated-null normalization and `policy_weakening.py` classifier that supply the corrective bundle/diff behavior, and the `code_sources.py` intake and `code_discovery.py` artifact production behind `trustweave discover`. The scope remains narrower than the complete package; CLI parsing, report rendering, importers, and other adapters are not mutated by this diagnostic.

## The discovery layer in the gate

The gate originally covered fourteen modules and none of the three implementing
`trustweave discover`.
Measured before any work: **2,073 mutants, 1,474 killed, 581 survived — 71.7%**, against 96%
line-and-branch coverage on the same code. The whole run takes 160 seconds at ~55
mutations/second, so runtime was never the obstacle. Two of the three are now gated.

| Module | Before | Now | In the gate |
|---|---|---|---|
| `code_discovery.py` | 53.4% | **99.55%** | yes |
| `code_sources.py` | 69.8% | **90.70%** | yes, carried by the aggregate |
| `code_analysis.py` | ~70% | **78.79%** | no, and the reason is measured below |

### What moved `code_discovery.py` from 53% to 99.55%

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

### Why `code_sources.py` stops at 90.70%

Three survivors this section previously listed as unkillable have since been killed, which
is why the figure moved from 88.4%. Two were the `InputOutputError` messages raised on a
stat failure and a read failure. Those messages are output a reviewer reads, and the
inventory's own policy forbids excusing a change to observable output as equivalent, so
they are asserted now; the failures are injected rather than provoked with file
permissions, which makes the tests deterministic for any user on any platform, and the
`# pragma: no cover` on the stat path is gone with the coverage it excused. The third was
dropping the explicit `encoding`, which is not an equivalence at all: it falls back to the
platform locale, and on a POSIX or ASCII locale that records a valid UTF-8 module as
`file_is_not_utf8`. The assertion normalizes through the codec registry, so it kills the
fallback while leaving the `UTF-8` spelling correctly classified as equivalent.

Its twelve remaining survivors cannot be killed:

| Count | Survivor | Why |
|---|---|---|
| 8 | the `path_escapes_analyzed_root` branch | unreachable: the walk already skips symlinked files and prunes symlinked directories, so `os.walk` never yields a candidate whose resolved path escapes the resolved root |
| 3 | `followlinks=None` / omitted / `True` | equivalent: `None` is falsy, the parameter defaults to `False`, and the loop reassigns `subdirectories[:]` to exclude every symlinked directory whatever `followlinks` says |
| 1 | `encoding="UTF-8"` | equivalent: both spellings resolve to one codec |

One of the eight is instructive. `skipped.append(None)` survives, yet if that branch ever
ran it would raise `AttributeError` in the final sort over `relative_path`. Nothing reaches
it, which is the proof, and no test can be written that does without first removing the
symlink handling the branch exists to back up.

Passing 95% on that module alone would mean deleting a defence-in-depth check or contriving
a test for a state the code cannot reach. It is gated anyway, because the gate scores the
aggregate and the module's shortfall is small against the total.

### `code_analysis.py` is measured and still not gated

The earlier estimate here was "~1,100 mutants, ~334 surviving, ~70%". Adding the module to
the scope and running it gives the real figures: **1,509 mutants, 1,189 killed, 320
surviving, 78.79%**, and an aggregate of 94.74% across seventeen modules, which is below
the 95% threshold.

Two rounds of targeted work were done before deciding, and the yield is what settles it.

The first round followed the lever that worked on `code_discovery.py`. Across the 46 cases
in `tests/test_code_analysis.py` a signal's `symbol` and `line` were never asserted at all,
so any mutation corrupting the evidence a reviewer reads was invisible.
`tests/test_code_analysis_evidence.py` drives the catalogue itself -- every symbol, receiver
method, command, environment name, credential path and SQL verb the analyzer claims to
recognise -- and asserts the whole signal. 269 cases. It moved the module 77.64% to 78.26%.

The second round targeted the receiver branches, where 74 of the survivors sat.
`tests/test_code_analysis_receivers.py` covers the four shapes an effect travels through:
inline on a constructor, a local receiver behind an attribute chain, a receiver stored on
`self` in `__init__`, and an attribute bound to a symbol. 74 cases. It moved the module
78.26% to 78.79%.

**343 tests bought 1.15 points.** What remains is not a coverage gap of the kind the first
two modules had. Sampling it shows unreachable argument defaults -- `.get(attr, "")` where
the key is always present -- and refusal-reason and action-class string literals on branches
whose corrupted value is then absorbed by the precedence fallback, so no public result
changes. Reaching 95% would need roughly 280 further kills at three to eight per round of
that size, and the gate additionally requires a recorded proof for every survivor; writing
320 of those honestly is not possible, because most are not equivalences.

So the module stays out, and this is now a measured decision rather than an estimate. The
tests are kept: they are worth having whether or not the module is gated, and they are what
found the three defects recorded in the changelog. One of them was found by the gate's own
coverage accounting rather than by a survivor -- 18 mutants reported as having no covering
test at all, every one of them in `_env_is_secret`, a function that was defined, never
called, and fully superseded by `_environ_class`. It has been deleted.

## Recorded run

| Field | Evidence |
| --- | --- |
| Date | 2026-09-07 |
| Tool | `mutmut 3.7.0` |
| Platform | Linux with fork support |
| Mutated source | `src/trustweave/engine.py`, `models.py`, `policy_predicates.py`, `policy_review.py`, `chain.py`, `findings.py`, `risk.py`, `evidence.py`, `config.py`, `schema_catalog.py`, `sarif.py`, `commands/ci.py`, `bundle_policy.py`, `policy_weakening.py`, `code_sources.py`, and `code_discovery.py` |
| Fixture copy | Repository workflows, Docker assets, executable scripts, contract fixtures, schemas, examples, policies, scenarios, documentation, and public README assets are copied into the mutation workspace. |
| Test selection | `tests -k 'not repository_reality_check and not reality_check_contracts'`. The repository-reality subprocess test and its isolated-wheel contract test are excluded because instrumented source imports the mutation runtime, while those tests deliberately build a dependency-free isolated wheel. The ordinary release verification continues to execute both tests. |
| Result | 7,369 generated mutants; 7,222 killed; 147 survived; 0 without a selected test; 0 timed out; 0 suspicious. |
| High-risk scope score | 7,222 killed / 7,369 generated (98.01% killed) |
| Hosted gate | `.github/workflows/mutation.yml` runs this Linux-only scope and enforces the 95% threshold, exact survivor-identifier parity, exact normalized survivor-diff/triage parity, no duplicate IDs, zero untriaged records, and zero `needs_regression` classifications. |

## Interpretation and survivor triage

The current sixteen-module measurement reaches the owner-required **95% mutation threshold** for the measured high-risk scope. It is not a package-wide mutation-quality claim and does not establish that the package is secure.

Every survivor from this run has an individual source-level diff and an explicit classification in [`mutation-survivor-triage-v1.json`](mutation-survivor-triage-v1.json). The regenerated inventory records **147 classified survivors**, **0 untriaged survivors**, **147 equivalent mutations**, **0 defensive mutations**, and **0 mutations marked `needs_regression`**. The 19 `policy_weakening.py` survivors are limited to unreachable strict-parser defaults, unique-position ordering forms, and normalization predicates; the inventory preserves their exact diffs and code-level proofs. Each equivalent record preserves a code-level proof that the changed expression is semantically redundant or unreachable under the strict local contracts.

Equivalent classifications are limited to code-proven semantic redundancies or unreachable control flow that cannot alter a successful public result, validation result, or reviewer-facing diagnostic. The inventory preserves the exact mutmut diff and rationale for every record; [`MUTATION_EQUIVALENCE_AUDIT.md`](MUTATION_EQUIVALENCE_AUDIT.md) records the security-focused review performed after the killed non-fail-closed approval-boundary mutant was reproduced. **This measurement satisfies the local zero-`needs_regression` and zero-untriaged requirements; final acceptance additionally requires the hosted parity gate to pass on the same commit SHA.**

The prior twelve-module and fourteen-module measurements are superseded by this current configured run. Historical measurements must not be compared as though they represented the final high-risk scope result.

## Re-run procedure

Install the development dependencies on a POSIX environment with fork support, then run the following from a clean checkout.

```bash
python -m pip install -e ".[dev]"
rm -rf mutants .mutmut-cache
env -u GITHUB_SHA mutmut run 2>&1 | tee mutation-run.log
mutmut results --all true > mutation-results.txt
python scripts/mutation_gate.py
rm -rf mutants .mutmut-cache
```

`GITHUB_SHA` is unset because mutmut otherwise restricts mutants to the commit's diff,
which silently shrinks the scope. The last command is the gate itself: the hosted job runs
`scripts/mutation_gate.py` with the same arguments, so a run that passes here passes there.
It enforces the 95% threshold, exact survivor-identifier parity against
[`mutation-survivor-triage-v1.json`](mutation-survivor-triage-v1.json), exact
normalized-diff parity so a pinned diff cannot drift from the mutant it describes, no
duplicate or stale records, zero untriaged survivors, a non-empty rationale on every
record, and zero `needs_regression` classifications. A new survivor therefore fails the
gate until it is either killed or classified with a recorded proof.

The project configuration in `pyproject.toml` defines the sixteen-module source scope, workspace fixture copies, and selected tests. The `mutants/` directory and `.mutmut-cache/` directory are generated output and must not be committed. The hosted Linux gate records `mutation-run.log`, `mutation-results.txt`, and `mutation-quality.json` as workflow evidence.

## Why this is Linux-only

The mutmut documentation states that its current execution model requires fork support and therefore needs WSL on Windows. TrustWeave supports Windows for its ordinary test suite, so making mutation analysis a required Windows gate would be misleading and brittle. The named hosted gate is Linux-only; it is a release-blocking quality check for the declared mutation scope, not a portability claim.

## References

[1]: https://mutmut.readthedocs.io/ "mutmut documentation"
