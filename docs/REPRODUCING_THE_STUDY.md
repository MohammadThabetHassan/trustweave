# Reproducing the study's measurements

This is about the **research measurements** — how much published policy lies inside the
decidable fragment and the checks behind those numbers. For the separate question of whether the *tool* produces byte-identical output from the same
inputs, see the [reproducibility and integrity contract](REPRODUCIBILITY.md).

Every measured figure in this project comes from a script in `scripts/` and is recorded in an
artifact in `docs/`. Nothing is hand-entered. This page says how to re-derive them from
scratch, what should match, and what cannot be checked from this repository alone.

## Why the manuscript is not here

The write-up lives in a separate private repository. A journal's similarity check reads a
publicly posted full text as prior dissemination, so the manuscript is kept out of a public
repository on purpose. What stays here is everything a reader needs to check the work: the
instruments, the artifacts they produced, and the corpus commits they read.

The guard that keeps the manuscript honest, `scripts/check_manuscript.py`, therefore takes
the manuscript's path from outside the repository:

```bash
TRUSTWEAVE_PAPER=/path/to/main.tex python scripts/check_manuscript.py
```

It fails if a figure in the manuscript disagrees with the artifact it came from, if a pinned
sentence has been reworded so the pin no longer reaches it, if a plotted figure series drifts
from its artifact, or if the bibliography and the artifacts disagree about which corpus
commit was read. Without `TRUSTWEAVE_PAPER` it has nothing to check and says so; the tests
that exercise it skip rather than pass.

## What you need

- Python 3.11 or newer, and `pip install -e ".[dev]"`.
- [`opa`](https://github.com/open-policy-agent/opa) 1.20.2, for the Rego adapter and for the
  differential oracle that checks it. Other versions may flag a different set of
  nondeterministic builtins, which changes two verdicts.
- About 1 GB of disk and a network connection, for the corpora.
- `z3-solver` (installed by the `dev` extra) for the witness-space check.

The corpora are **not** vendored. They belong to their authors, and several licences do not
permit redistribution, so this repository records where each one was and at which commit
rather than copying it.

## Re-deriving everything

### 1. Put the corpora on disk at the commits the artifacts record

```bash
python scripts/clone_pinned_corpora.py --into /tmp/corpora
```

It reads the `corpus` block of every whole-corpus artifact, so the list cannot drift from the
measurement. It refuses a checkout that did not finish: a blobless clone fetches file
contents lazily, and a partial checkout still answers `git rev-parse HEAD` correctly, which
is how one measurement came to read a fifth of its repository and record the commit for all
of it. Re-running repairs a partial tree rather than only reporting on it.

### 2. Re-measure and diff against what is committed

```bash
python scripts/verify_corpus_provenance.py --corpora /tmp/corpora
```

This re-runs each adapter over the same root with the same scope and compares
`policies_considered` and the verdict counts against the committed artifact. All seven
whole-corpus artifacts should reproduce exactly. The five it skips say why: three are the
smaller corpora joined to a suite study rather than measured whole, the Cedar archive's
policies are sealed inside an archive the corpus tracks, which the check does not unpack, and
the third-party Kyverno sample records its provenance in a manifest of its own
(`docs/third-party-kyverno-corpus-v1.json`).

The same check runs monthly in CI (`.github/workflows/provenance.yml`) and on request. A
failure there can mean a corpus moved rather than a defect here, and the report distinguishes
the two.

### 3. Regenerate an individual measurement

Each artifact names the script that produced it. The ones behind the headline table:

```bash
# membership, one ecosystem at a time
python scripts/fragment_membership.py azure /tmp/corpora/fragment-membership-azure-wide-v1/azure-policy \
  --wide --json docs/fragment-membership-azure-wide-v1.json

# the pooled taxonomy, computed from the membership artifacts
python scripts/exclusion_taxonomy.py --json docs/exclusion-taxonomy-v1.json
```

Cedar has a second artifact and it is deliberately not the Cedar row:

```bash
# the 7,497 .cedar policies sealed inside the corpus's own corpus-tests.tar.gz
python scripts/fragment_membership.py cedar /tmp/corpora/cedar-integration-tests \
  --archive --json docs/fragment-membership-cedar-archive-v1.json
```

That archive is the output of a coverage-guided fuzz run, so folding it into the Cedar row
would make machine-generated input more than half of the whole cross-language corpus.
`--wide` still walks the 22 tracked files that the published row measures; the archive is
measured, labelled and reported separately so that the exclusion is a decision on the record
rather than a `getattr` fallback nobody made.

`docs/coverage-cost-v1.json` is deliberately absent from that list. Its distribution is
withdrawn — the grouping rule behind it under-counted set-membership guards — and the artifact
carries an `invalidated` block saying so. `scripts/coverage_cost.py` refuses to overwrite it
without `--replace-invalidated`, so a re-run of this page cannot quietly turn a retraction back
into a measurement.

### 4. Re-run the checks that hold the instruments to something other than themselves

```bash
# the Rego membership adapter against the engine's own dependency analysis
python scripts/oracle_rego.py /tmp/corpora/fragment-membership-rego-gcp-v1 \
  /tmp/corpora/fragment-membership-rego-wide-v1 --dynamic --json docs/oracle-rego-v1.json

# the decision map the theory is stated over, against the evaluator that ships
python scripts/interpreter_oracle.py --json docs/interpreter-oracle-v1.json

# the Kyverno membership adapter against the engine that runs the policies: every suite as
# shipped, under injected namespace labels, and with its external stubs removed
python scripts/oracle_kyverno.py corpora/kyverno --json docs/oracle-kyverno-v1.json

# the witness construction against an SMT solver, and against the closed-form criterion
python scripts/verify_witness_space.py --json docs/witness-space-verification-v1.json
```

`interpreter_oracle.py` is seeded and should reproduce its recorded counts exactly.
`oracle_rego.py` needs `opa` on `PATH`; `oracle_kyverno.py` needs `kyverno` on `PATH` and
the corpus checkout `docs/fragment-membership-kyverno-wide-v1.json` records.

The sampling-error rows of `docs/estimator-comparison-v1.json` are exact at every sample
size: the script sums the hypergeometric mass rather than enumerating or simulating samples.

```bash
python scripts/estimator_comparison.py --policy policies/default-policy.json \
  --scenarios scenarios/default-scenarios.json scenarios/adversarial-scenarios.json \
  scenarios/coverage-matrix-scenarios.json --json docs/estimator-comparison-v1.json
```

### 4a. The two studies that use exact equivalence as ground truth

Both run under [`EXACT_EVALUATION_PROTOCOL.md`](EXACT_EVALUATION_PROTOCOL.md), whose hash the
script fixes and checks; they need no corpus and no network.

```bash
python scripts/exact_evaluation_study.py sample --json docs/generated-policy-sample-v1.json
python scripts/exact_evaluation_study.py suites \
  --sample docs/generated-policy-sample-v1.json --json docs/suite-strategy-study-v1.json
python scripts/exact_evaluation_study.py review \
  --sample docs/generated-policy-sample-v1.json --json docs/review-signal-study-v1.json
```

### 4b. The samples of policy written outside the vendors

Drawing a sample needs GitHub code search and is not repeatable, which is why nothing
depends on repeating it: each manifest pins every file by repository, path, commit and the
SHA-256 of its bytes. Measuring re-fetches exactly those files and refuses any that changed.

```bash
# measure a pinned sample (Kyverno, IAM and Cedar are judged one file at a time)
python scripts/measure_third_party_policies.py \
  --corpus docs/third-party-sample-kyverno-corpus-v1.json \
  --json docs/third-party-sample-kyverno-membership-v1.json
# Rego is judged with each repository's whole bundle, checked out at the pinned commit
python scripts/third_party_sample.py measure-rego \
  --corpus docs/third-party-sample-rego-corpus-v1.json --work /tmp/rego-bundles \
  --json docs/third-party-sample-rego-membership-v1.json
# the table beside the vendor rows
python scripts/third_party_sample.py summarise --json docs/third-party-sample-summary-v1.json
# re-fetch the original 49 and say how any failure failed
python scripts/measure_third_party_policies.py --revalidate \
  --json docs/third-party-kyverno-revalidation-v1.json
# the sampled Rego modules against the engine's own dependency analysis
python scripts/third_party_sample.py oracle-rego \
  --corpus docs/third-party-sample-rego-corpus-v1.json --work /tmp/rego-bundles \
  --json docs/third-party-sample-rego-oracle-v1.json
```

### 4c. The suite-strategy study on real Cedar policy

Runs under [`EXACT_EVALUATION_PROTOCOL_CEDAR.md`](EXACT_EVALUATION_PROTOCOL_CEDAR.md). Every
decision is the Cedar engine's, through its Python bindings, which are not a dependency of the
package: `pip install cedarpy==4.12.1` first. That binding bundles the engine cedar-policy
4.12.0, as its software bill of materials records; the protocol gives the binding's version,
4.12.1, as the engine's. The files are re-fetched by the pins of the Cedar sample manifest, so
this needs the network once.

```bash
python scripts/cedar_exact_study.py study --cache /tmp/cedar-cache \
  --json docs/cedar-suite-strategy-study-v1.json
python scripts/cedar_exact_study.py edits --cache /tmp/cedar-cache \
  --history HISTORY.json --json docs/cedar-real-edits-v1.json
```

`HISTORY.json` lists, per sampled file, the commits that touched it, as GitHub's
`repos/{owner}/{repo}/commits?path=` returns them; `docs/cedar-real-edits-v1.json` pins every
pair it measured by commit and SHA-256, so re-deriving the pairs does not depend on it.

### 4d. What a real suite's line coverage is worth (Gatekeeper Rego)

Runs under [`SUITE_ADEQUACY_PROTOCOL_REGO.md`](SUITE_ADEQUACY_PROTOCOL_REGO.md). Needs `opa`
on `PATH` and the pinned Gatekeeper library (a cloned corpus, commit in the artifact's `corpus`
block). For each module with an author-written suite it records the suite's line coverage and
its mutation score, every number from `opa test`.

```bash
python scripts/rego_suite_study.py study \
  --corpus /path/to/gatekeeper-library \
  --json docs/rego-suite-adequacy-v1.json
```

This is a different measurement from the decision-blindness prediction of §4 above: it reports
line coverage against a located-source mutation score (`scripts/rego_source_mutation.py`), where
`scripts/rego_mutation.py` reports a text-search mutation score against the decision-coverage
flag. The protocol states how the two operator sets differ.

### 5. The whole gate

```bash
ruff format --check . && ruff check . && mypy src
python scripts/reality_check.py
python -m pytest -q                      # coverage gate at 95%
python scripts/mutation_gate.py --help   # the survivor gate CI gives its own job
```

## What this repository cannot check

- **The manuscript**, unless you point `TRUSTWEAVE_PAPER` at it.
- **Four of the six membership adapters have no external oracle.** Rego's is checked
  against the engine's own dependency analysis, because `opa deps` answers the question the
  adapter asks; Kyverno's is checked behaviourally, by running every measured policy's suite
  under the Kyverno CLI as shipped, under injected cluster state, and with the stubs its
  authors supplied removed (`docs/oracle-kyverno-v1.json`). Cedar ships a command-line
  evaluator that could support the same check; that is future work, not an impossibility,
  and the write-up says so.
- **A third-party corpus can decay.** Its files live in repositories nobody here controls.
  An earlier re-fetch of the 49 Kyverno files reported 18 gone; it counted every failed
  request as a missing file, and a re-fetch with retries verified all 49
  (`docs/third-party-kyverno-revalidation-v1.json` records both runs). Every sample
  manifest can be re-checked the same way, and a file that has gone is reported with how its
  fetch failed rather than silently dropped.
- **43 Azure definitions are declined rather than judged.** They name a Gatekeeper
  ConstraintTemplate at an HTTPS URL, so their guard is a Rego program the definition does not
  contain, and an offline procedure has nothing to read. The URL is recorded in the artifact,
  so the refusal can be lifted by fetching rather than by re-deriving anything.
