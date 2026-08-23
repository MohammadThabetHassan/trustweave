#!/usr/bin/env bash
# Full TrustWeave review of the research-assistant demo.
#
# Story: someone proposes relaxing the Slack approval rule "to save time".
# Part 1 reviews the current setup. Part 2 diffs the candidate against it.
#
# Requires: python 3.11+, trustweave installed (pip install trustweave)
set -euo pipefail

cd "$(dirname "$0")"
rm -rf artifacts

echo "== 1/4 Scan declared boundaries =="
trustweave scan \
  --manifest manifests/research-agent.manifest.json \
  --policy policies/boundary-policy.json \
  --output-dir artifacts

echo "== 2/4 Run policy regression scenarios =="
trustweave test \
  --policy policies/boundary-policy.json \
  --scenarios scenarios/regressions.json \
  --output-dir artifacts

echo "== 3/4 Attest and build the human-readable report =="
trustweave attest --source-revision local --output-dir artifacts
trustweave report --output-dir artifacts

echo "== 4/4 Diff the candidate policy against the reviewed baseline =="
trustweave scan \
  --manifest manifests/research-agent.manifest.json \
  --policy policies/candidate-relaxed.json \
  --output-dir artifacts/candidate
trustweave diff \
  --base artifacts/agent-security-bundle.json \
  --head artifacts/candidate/agent-security-bundle.json \
  --output-dir artifacts/diff

echo
echo "Done."
echo "  Current review:      artifacts/report.md"
echo "  Candidate diff:      artifacts/diff/bundle-diff.md"
