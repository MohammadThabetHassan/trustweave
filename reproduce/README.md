# Reproducing the paper's measurements

Every number the paper reports is read from a JSON artifact under `docs/`, and every artifact
is written by a script under `scripts/`. This directory holds the environment those scripts
ran in and the shortest route through them. `docs/REPRODUCING_THE_STUDY.md` explains the
membership measurement in more depth.

The manuscript itself is not in this repository. `scripts/check_manuscript.py` compares every
number the manuscript states against these artifacts (318 claims), and it runs wherever the
manuscript is; elsewhere it reports that there is nothing to check.

## The image

```bash
docker build -f reproduce/Dockerfile -t trustweave-reproduce .
docker run --rm trustweave-reproduce verify
```

`reproduce/Dockerfile` pins the tools at the versions the artifacts record and checks every
binary against its release's published SHA-256:

| Tool | Version | Used by |
|---|---|---|
| OPA | 1.20.2 | the Rego adapter, the Rego oracle and every Rego study |
| Kyverno CLI | 1.19.1 | the Kyverno oracle and mutation study |
| `cedarpy` | 4.12.1 | every Cedar decision |
| `cedar-policy-cli`, experimental build | 4.12.0 | the SymCC check (`cedar symcc`) |
| cvc5, static build | 1.3.1 | the solver SymCC calls |
| `z3-solver` | from the `dev` extra | the solver check of the witness construction |
| A JDK | the distribution's default | builds and runs XPA and the Balana harness for the XACML comparison |

`reproduce/run.sh` is the image's entry point. It has four modes:

| Mode | What it does | Network | Time |
|---|---|---|---|
| `verify` | tool versions; `scripts/check_protocols.py`; the study scripts' tests; `scripts/verify_witness_space.py` | none | minutes |
| `corpora` | clones every corpus the membership artifacts name, at the recorded commit, into `$CORPORA` (default `/corpora`) | yes | about 1 GB |
| `membership` | re-measures every whole-corpus artifact and diffs the counts (`scripts/verify_corpus_provenance.py`) | none after `corpora` | about an hour |
| `symcc` | re-runs SymCC's check of the Cedar verdicts and prints its summary beside the committed one | once, for the files and schemas | under an hour on eight cores |
| `xacml` | fetches XPA, Balana's conformance cases and Z3 4.6.0 at their pinned versions, builds them, re-runs the comparison with Xu et al.'s criteria and prints its summary beside the committed one | once, for the tools | well under an hour |

Mount a volume to keep the corpora between runs:

```bash
docker run --rm -v "$PWD/corpora:/corpora" trustweave-reproduce corpora
docker run --rm -v "$PWD/corpora:/corpora" trustweave-reproduce membership
```

CI builds the image and runs `verify` on every pull request that touches the scripts, the
artifacts or the protocols (`.github/workflows/reproduce.yml`).

## Pre-registration

A pre-registered study's protocol, under `docs/*PROTOCOL*.md`, was committed before the study
ran, and its SHA-256 is fixed in the study script. Each script refuses to run on its
population if the protocol differs, and each artifact records the hash it ran under.
`python scripts/check_protocols.py` checks that every artifact names a protocol the repository
holds. A protocol's hash is taken with line endings normalised to LF.

## Each artifact and the command that writes it

`<C>` is the directory `run.sh corpora` fills; `<GK>` is
`<C>/fragment-membership-rego-wide-v1/gatekeeper-library`, the Gatekeeper library at
`e034212e94e6`. Commands are run from the repository root.

**From the artifacts alone.** No corpus, no engine, no network; most finish in seconds, and a
unit test recomputes most of them and compares with the committed file.

| Artifact | Command |
|---|---|
| `exclusion-taxonomy-v1` | `python scripts/exclusion_taxonomy.py --json docs/exclusion-taxonomy-v1.json` |
| `exclusion-crosstab-v1` | `python scripts/exclusion_taxonomy.py --crosstab-json docs/exclusion-crosstab-v1.json` |
| `review-round-analyses-v1` | `python scripts/review_round_analyses.py --json docs/review-round-analyses-v1.json` (post hoc, not pre-registered) |
| `third-party-sample-summary-v1` | `python scripts/third_party_sample.py summarise --json docs/third-party-sample-summary-v1.json` |
| `decision-threshold-analysis-v1` | `python scripts/decision_threshold_analysis.py --json docs/decision-threshold-analysis-v1.json` |
| `decision-trend-test-v1` | `python scripts/decision_trend_test.py --json docs/decision-trend-test-v1.json` |
| `fragment-stratified-test-v1` | `python scripts/fragment_stratified_test.py --json docs/fragment-stratified-test-v1.json` |
| `estimator-comparison-v1` | `python scripts/estimator_comparison.py --policy policies/default-policy.json --scenarios scenarios/default-scenarios.json scenarios/adversarial-scenarios.json scenarios/coverage-matrix-scenarios.json --json docs/estimator-comparison-v1.json` |
| `interpreter-oracle-v1` | `python scripts/interpreter_oracle.py --json docs/interpreter-oracle-v1.json` |
| `witness-space-verification-v1` | `python scripts/verify_witness_space.py --json docs/witness-space-verification-v1.json` |
| `generated-policy-sample-v1` | `python scripts/exact_evaluation_study.py sample --json docs/generated-policy-sample-v1.json` |
| `suite-strategy-study-v1` | `python scripts/exact_evaluation_study.py suites --sample docs/generated-policy-sample-v1.json --json docs/suite-strategy-study-v1.json` |
| `review-signal-study-v1` | `python scripts/exact_evaluation_study.py review --sample docs/generated-policy-sample-v1.json --json docs/review-signal-study-v1.json` |

**Membership.** Each whole-corpus artifact is one adapter run over one clone; `run.sh
membership` re-runs all of them and diffs the counts.

| Artifact | Command |
|---|---|
| `fragment-membership-azure-wide-v1` | `python scripts/fragment_membership.py azure <C>/fragment-membership-azure-wide-v1/azure-policy --wide --json ...` |
| `fragment-membership-cedar-wide-v1` | `python scripts/fragment_membership.py cedar <C>/fragment-membership-cedar-wide-v1/cedar-integration-tests --wide --json ...` |
| `fragment-membership-cedar-archive-v1` | the same checkout, with `--archive` in place of `--wide` |
| `fragment-membership-rego-wide-v1` | `python scripts/fragment_membership.py rego <C>/fragment-membership-rego-wide-v1 --wide --json ...` |
| `fragment-membership-rego-gcp-v1` | `python scripts/fragment_membership.py rego <C>/fragment-membership-rego-gcp-v1 --wide --json ...` |
| `fragment-membership-xacml-wide-v1` | `python scripts/fragment_membership.py xacml <C>/fragment-membership-xacml-wide-v1 --wide --json ...` |
| `fragment-membership-kyverno-thirdparty-v1` | `python scripts/measure_third_party_policies.py --json ...` (fetches the 49 pinned files) |
| `third-party-kyverno-revalidation-v1` | `python scripts/measure_third_party_policies.py --revalidate --json ...` |
| `corpus-provenance-verification-v1` | `python scripts/verify_corpus_provenance.py --corpora <C> --json ...` |
| `azure-initiative-bindings-v1` | `python scripts/azure_initiative_bindings.py --corpus <C>/fragment-membership-azure-wide-v1/azure-policy --json ...` |
| `guard-certification-v1` | `python scripts/guard_certification.py --corpora <C> --json ...` (pre-registered; OPA; re-measures every corpus first and fetches the third-party Kyverno files) |

**Oracles.** Each checks an adapter or an engine against another reading of the same policies.

| Artifact | Command |
|---|---|
| `oracle-rego-v1` | `python scripts/oracle_rego.py <C>/fragment-membership-rego-gcp-v1 <C>/fragment-membership-rego-wide-v1 --dynamic --json ...` |
| `oracle-kyverno-v1` | `python scripts/oracle_kyverno.py <C>/fragment-membership-kyverno-wide-v1/kyverno --json ...` |
| `kyverno-mutation-v1` | `python scripts/kyverno_mutation.py <C>/fragment-membership-kyverno-wide-v1/kyverno --coverage docs/suite-coverage-kyverno-v1.json --comparison 40 --json ...` |
| `third-party-sample-rego-oracle-v1` | `python scripts/third_party_sample.py measure-rego --corpus docs/third-party-sample-rego-corpus-v1.json --work W --json docs/third-party-sample-rego-membership-v1.json`, then `oracle-rego` with the same `--corpus` and `--work` |

**Studies on real policy.** These are the long runs. All but the gaps and stillborn readings
are pre-registered.

| Artifact | Command | Needs |
|---|---|---|
| `rego-suite-adequacy-v1` | `python scripts/rego_suite_study.py study --corpus <GK> --json ...` | OPA; hours |
| `rego-exact-adequacy-v1` | `python scripts/rego_exact_study.py study --corpus <GK> --json ...` | OPA; hours |
| `rego-exact-adequacy-schemas-v1` | `python scripts/rego_exact_study.py study --corpus <GK> --population schemas --json ...` | OPA; hours |
| `rego-exact-gaps-v1` | `python scripts/rego_exact_study.py gaps --corpus <GK> --artifact docs/rego-exact-adequacy-v1.json --json ...` | OPA |
| `rego-suite-stillborn-v1` | `python scripts/rego_exact_study.py stillborn --corpus <GK> --json ...` | OPA |
| `rego-suite-strategy-study-v1` | `python scripts/rego_payoff_study.py study --corpus <GK> --json ...` | OPA; hours |
| `rego-real-faults-v1` | `python scripts/rego_real_faults_study.py study --corpora R --workers 6 --json ...` | OPA, full histories (below); hours |
| `cedar-suite-strategy-study-v1` | `python scripts/cedar_exact_study.py study --cache DIR --json ...` | `cedarpy`; network once |
| `combination-criteria-study-v1` | `python scripts/combination_criteria_study.py study --cache DIR --workers 6 --json ...` | `cedarpy`; the Cedar cache above; hours |
| `cedar-real-edits-v1` | `python scripts/cedar_exact_study.py edits --cache DIR --history HISTORY.json --json ...` | `cedarpy`; the history (below) |
| `cedar-schema-candidates-v1` | `python scripts/cedar_schema_candidates.py --cedar cedar --cache DIR --json ...` | the Cedar CLI; network once |
| `cedar-symcc-crosscheck-v1` | `run.sh symcc`, or `python scripts/cedar_symcc_crosscheck.py study --cedar cedar --cvc5 cvc5 --cache DIR --workers 8 --partial P.jsonl --json ...` | the Cedar CLI, cvc5, `cedarpy`; network once |
| `xacml-criteria-study-v1` | `run.sh xacml`, or `python scripts/xacml_criteria_study.py setup --tools DIR` then `study --tools DIR --json ...` | a JDK; `setup` fetches the rest; network once |

The real-faults study reads two repositories with their full history, because every fault is
read at its fix commit and at the commit's parent. It expects them at `R/rego/gatekeeper-library`
and `R/gcp/policy-library`:

```bash
git clone https://github.com/open-policy-agent/gatekeeper-library R/rego/gatekeeper-library
git -C R/rego/gatekeeper-library checkout e034212e94e666ab3ba69108d96222bffc8ef671
git clone https://github.com/GoogleCloudPlatform/policy-library R/gcp/policy-library
git -C R/gcp/policy-library checkout 4a2abc741583884dd38ca3b9bf2ff5a4d205a609
```

The clones `run.sh corpora` makes are blobless and laid out by artifact, so they do not serve
here.

## What does not reproduce exactly, and why

- **The third-party samples were drawn by GitHub code search** (`third_party_sample.py
  harvest`, then `select`), which returns different results on different days. The manifests
  (`docs/third-party-sample-*-corpus-v1.json`) pin every file drawn by repository, commit, path
  and SHA-256, so every measurement made on the samples reproduces; the draw itself does not.
- **`cedar-real-edits-v1` needs a history file that is not kept**: for each sampled Cedar file,
  the commits that changed it, newest first, as GitHub's `commits?path=` listed them. The
  artifact records the commits and SHA-256 of both versions of every pair it measured, so each
  measured pair can be checked; the list of pairs it skipped is not recorded.
- **Two artifacts record no corpus commit.** `azure-initiative-bindings-v1` read the Azure
  corpus at the commit `fragment-membership-azure-wide-v1` records (`9780ba642eaf`), and
  `rego-suite-strategy-study-v1` read the Gatekeeper library at the commit
  `rego-exact-adequacy-v1` records (`e034212e94e6`).
- **`kyverno-mutation-v1` records no CLI version.** The Kyverno CLI in use was 1.19.1, the
  version `oracle-kyverno-v1` records.
- **`rego-real-faults-v1` records its engine as `opa opa 1.20.2`.** The script prefixed the
  engine's name twice; the engine was OPA 1.20.2, and the script has been corrected since.
- **`oracle-rego-v1`'s `root` fields read `gcp` and `rego`**, the corpus directories of an
  earlier layout. Run under `<C>`, those fields differ; the counts do not.
- **The SymCC check ran on Windows x86-64**, with the Windows builds of the same Cedar CLI
  release and cvc5 version that the image installs for Linux. The protocol names both builds'
  digests. A solver's time limit can be reached on one machine and not another, so a fresh
  run's "no answer" counts may differ; its verdicts should not.
- **The XACML comparison's MC/DC rows depend on the machine.** On the machine that ran the
  study, XPA's two MC/DC generators ran past the protocol's 30-minute limit on pluto3, so MC/DC
  is compared on ten policies. A faster machine may finish them and change those rows, so
  `run.sh xacml` can report the summary as different. The oracle, the mutants, the equivalent
  mutants and the quotient's figures do not depend on it.
