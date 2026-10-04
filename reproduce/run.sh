#!/usr/bin/env bash
# Reproduce the paper's measurements. Run inside the image reproduce/Dockerfile builds.
#
#   verify      minutes, no network: tool versions, the pre-registration check, the study
#               scripts' tests, and the solver check of the witness construction
#   corpora     clone every corpus the artifacts name, at the commit each records, into
#               /corpora (network; about 1 GB)
#   membership  re-measure every corpus and diff the counts against the artifacts
#               (needs `corpora`; about an hour)
#   symcc       re-run SymCC's check of the Cedar exact study's equivalence verdicts and
#               print its summary beside the committed one (network once, for the files and
#               schemas; under an hour on eight cores)
#   xacml       re-run the comparison with Xu et al.'s criteria: fetch XPA, Balana's
#               conformance cases and Z3 4.6.0 at their pinned versions, build, run, and print
#               the summary beside the committed one (network once)
#
# The other pre-registered studies run for hours each; reproduce/README.md gives their
# commands.
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-verify}"
corpora="${CORPORA:-/corpora}"

case "$mode" in
  verify)
    echo "== tools"
    opa version | head -1
    kyverno version 2>/dev/null | head -1 || true
    cedar --version
    cvc5 --version | head -1
    python -c 'from importlib.metadata import version; print("cedarpy", version("cedarpy"), "z3", version("z3-solver"))'
    echo "== every pre-registered artifact names a protocol the repository holds"
    python scripts/check_protocols.py
    echo "== the study scripts' tests"
    python -m pytest -q -o addopts="" \
      tests/test_rego_witness_space.py tests/test_rego_payoff_study.py \
      tests/test_rego_real_faults_study.py tests/test_exact_evaluation_study.py \
      tests/test_cedar_exact_study.py tests/test_cedar_schema_candidates.py \
      tests/test_cedar_symcc_crosscheck.py tests/test_xacml_criteria_study.py \
      tests/test_check_manuscript.py \
      tests/test_reproduce_protocols.py
    echo "== the witness construction, against the solver"
    python scripts/verify_witness_space.py
    ;;
  corpora)
    python scripts/clone_pinned_corpora.py --into "$corpora"
    ;;
  membership)
    python scripts/verify_corpus_provenance.py --corpora "$corpora"
    ;;
  symcc)
    out="${OUT:-/tmp/symcc}"
    mkdir -p "$out"
    python scripts/cedar_symcc_crosscheck.py study --cedar /usr/local/bin/cedar \
      --cvc5 /usr/local/bin/cvc5 --cache "$out/cache" --workers "${WORKERS:-8}" \
      --partial "$out/partial.jsonl" --json "$out/cedar-symcc-crosscheck-v1.json"
    python - "$out/cedar-symcc-crosscheck-v1.json" <<'PY'
import json, sys
fresh = json.load(open(sys.argv[1], encoding="utf-8"))["summary"]
committed = json.load(open("docs/cedar-symcc-crosscheck-v1.json", encoding="utf-8"))["summary"]
for part in ("files", "primary", "secondary"):
    same = fresh[part] == committed[part]
    print(f"{part}: {'the same as committed' if same else 'DIFFERS from committed'}")
    if not same:
        print(json.dumps({"fresh": fresh[part], "committed": committed[part]}, indent=1))
PY
    ;;
  xacml)
    out="${OUT:-/tmp/xacml}"
    mkdir -p "$out"
    python scripts/xacml_criteria_study.py setup --tools "$out/tools"
    python scripts/xacml_criteria_study.py study --tools "$out/tools" \
      --workers "${WORKERS:-4}" --json "$out/xacml-criteria-study-v1.json"
    python - "$out/xacml-criteria-study-v1.json" <<'PY'
import json, sys
fresh = json.load(open(sys.argv[1], encoding="utf-8"))
committed = json.load(open("docs/xacml-criteria-study-v1.json", encoding="utf-8"))
for part in ("oracle", "summary", "hypotheses"):
    same = fresh[part] == committed[part]
    print(f"{part}: {'the same as committed' if same else 'DIFFERS from committed'}")
    if not same:
        print(json.dumps({"fresh": fresh[part], "committed": committed[part]}, indent=1))
PY
    ;;
  *)
    echo "unknown mode: $mode (verify, corpora, membership, symcc or xacml)" >&2
    exit 2
    ;;
esac
