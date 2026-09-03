#!/usr/bin/env bash
# Run one checked-in synthetic declaration-consistency fixture locally.
# This compares supplied static labels only; it does not import or execute a framework.
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^TW-COMP-[0-9]{3}$ ]]; then
  echo "Usage: $0 TW-COMP-NNN" >&2
  exit 2
fi

case_id="$1"
root="$(cd "$(dirname "$0")/../.." && pwd)"
export PYTHONPATH="$root/src${PYTHONPATH:+:$PYTHONPATH}"
output_dir="$root/demo/declaration-consistency/artifacts/$case_id"

rm -rf "$output_dir"
mkdir -p "$output_dir"

printf '== TrustWeave declaration-consistency walkthrough ==\n'
printf 'Case: %s\n' "$case_id"
printf 'Boundary: supplied local static labels only; no framework execution.\n\n'

printf '$ python3 scripts/run_declaration_completeness_benchmark.py --case %s --check\n' "$case_id"
python3 "$root/scripts/run_declaration_completeness_benchmark.py" --case "$case_id" --check
printf '\n'

printf '$ python3 scripts/verify_declaration_completeness_provenance.py\n'
python3 "$root/scripts/verify_declaration_completeness_provenance.py"
printf '\n'

printf '$ python3 scripts/run_declaration_completeness_benchmark.py --case %s --verify --output-dir demo/declaration-consistency/artifacts/%s\n' "$case_id" "$case_id"
python3 "$root/scripts/run_declaration_completeness_benchmark.py" \
  --case "$case_id" \
  --verify \
  --output-dir "$output_dir"
printf '\n'

printf '== Reviewer-facing local result ==\n'
sed -n '1,110p' "$output_dir/declaration-consistency-summary.md"
printf '\n'
printf 'Artifacts: demo/declaration-consistency/artifacts/%s/\n' "$case_id"
