# Reproducing the study's measurements

This is about the **research measurements** — how much published policy lies inside the
decidable fragment, what exhaustive coverage costs, and the checks behind those numbers. For
the separate question of whether the *tool* produces byte-identical output from the same
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
whole-corpus artifacts should reproduce exactly. The four it skips say why: three are the
smaller corpora joined to a suite study rather than measured whole, and the third-party
Kyverno sample records its provenance in a manifest of its own
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

# what exhaustive coverage costs on deployed cloud policy
python scripts/coverage_cost.py \
  --azure /tmp/corpora/fragment-membership-azure-wide-v1/azure-policy \
  --iam /tmp/corpora/fragment-membership-iam-wide-v1 \
  --json docs/coverage-cost-v1.json
```

### 4. Re-run the checks that hold the instruments to something other than themselves

```bash
# the Rego membership adapter against the engine's own dependency analysis
python scripts/oracle_rego.py /tmp/corpora/fragment-membership-rego-gcp-v1 \
  /tmp/corpora/fragment-membership-rego-wide-v1 --dynamic --json docs/oracle-rego-v1.json

# the decision map the theory is stated over, against the evaluator that ships
python scripts/interpreter_oracle.py --json docs/interpreter-oracle-v1.json

# the witness construction against an SMT solver
python scripts/verify_witness_space.py --json docs/witness-space-verification-v1.json
```

`interpreter_oracle.py` is seeded and should reproduce its recorded counts exactly.
`oracle_rego.py` needs `opa` on `PATH`.

### 5. The whole gate

```bash
ruff format --check . && ruff check . && mypy src
python scripts/reality_check.py
python -m pytest -q                      # coverage gate at 95%
python scripts/mutation_gate.py --help   # the survivor gate CI gives its own job
```

## What this repository cannot check

- **The manuscript**, unless you point `TRUSTWEAVE_PAPER` at it.
- **Five of the six membership adapters have no external oracle.** Only Rego's is checked
  against an engine, because `opa deps` answers the question the adapter asks. Kyverno and
  Cedar ship command-line evaluators that could support a behavioural check; that is future
  work, not an impossibility, and the write-up says so.
- **The third-party Kyverno corpus decays.** Its 49 files were sha256-verified when
  collected; re-fetching them later found 18 no longer available, from repositories renamed,
  deleted, or rewritten. `docs/third-party-kyverno-revalidation-v1.json` records that, and
  the measurement rests on the verification done at collection time.
- **57 Azure definitions are declined rather than judged.** They name a Gatekeeper
  ConstraintTemplate at an HTTPS URL, so their guard is a Rego program the definition does not
  contain, and an offline procedure has nothing to read. The URL is recorded in the artifact,
  so the refusal can be lifted by fetching rather than by re-deriving anything.
