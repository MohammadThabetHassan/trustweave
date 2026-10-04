#!/usr/bin/env bash
# Reproduce the paper's measurements. Run inside the image reproduce/Dockerfile builds.
#
#   verify      minutes, no network: tool versions, the pre-registration check, the study
#               scripts' tests, and the solver check of the witness construction
#   corpora     clone every corpus the artifacts name, at the commit each records, into
#               /corpora (network; a few GB)
#   membership  re-measure every corpus and diff the counts against the artifacts
#               (needs `corpora`; about an hour)
#
# The pre-registered studies run for hours each; reproduce/README.md gives their commands.
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-verify}"
corpora="${CORPORA:-/corpora}"

case "$mode" in
  verify)
    echo "== tools"
    opa version | head -1
    kyverno version 2>/dev/null | head -1 || true
    python -c 'import cedarpy, z3; print("cedarpy", cedarpy.__version__, "z3", z3.get_version_string())'
    echo "== every pre-registered artifact names a protocol the repository holds"
    python reproduce/check_protocols.py
    echo "== the study scripts' tests"
    python -m pytest -q -o addopts="" \
      tests/test_rego_witness_space.py tests/test_rego_payoff_study.py \
      tests/test_rego_real_faults_study.py tests/test_exact_evaluation_study.py \
      tests/test_cedar_exact_study.py tests/test_check_manuscript.py \
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
  *)
    echo "unknown mode: $mode (verify, corpora or membership)" >&2
    exit 2
    ;;
esac
