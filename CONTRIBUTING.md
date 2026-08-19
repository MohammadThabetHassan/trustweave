# Contributing to TrustWeave

Thank you for helping improve TrustWeave. The project welcomes contributions that make agent-security review more reproducible, understandable, and safe.

## Contribution principles

1. **Preserve the non-executing core.** Manifests and scenarios are data, not executable tool configurations. Do not add hidden command execution, network calls, credential discovery, or model calls to the core workflow.
2. **Add evidence with behavior.** A new policy feature, finding type, or scenario must include at least one deterministic test and explicit limits.
3. **Keep safety claims narrow.** Do not describe TrustWeave as preventing all prompt injection, proving a system secure, or replacing a security assessment.
4. **Use synthetic examples.** Tests and demonstration data must not contain real customer records, secrets, tokens, or third-party targets.
5. **Keep contracts stable.** Schema changes require a documented migration path and compatibility test.

## Before you contribute

Use the repository’s **Bug report** issue form for reproducible defects in TrustWeave and the **Bounded feature request** form for scoped ideas. For a larger change, describe the reviewer decision, deterministic evidence, tests, compatibility impact, and safety boundary before investing in an implementation. Suspected vulnerabilities must follow the private route in [SECURITY.md](SECURITY.md), not a public issue or pull request.

External contributors should propose a pull request from a branch or fork. Review, merge, tagging, signing, package publication, and GitHub Release creation remain owner-controlled actions; a successful local build or hosted check does not authorize them.

## Local development

```bash
python -m pip install -e ".[dev]" pip-audit

ruff format --check .
ruff check .
mypy src
bandit -r src/trustweave -q
pytest
python scripts/reality_check.py
python -m build
twine check dist/*
pip-audit -r requirements.txt
cyclonedx-py environment "$(which python)" --pyproject pyproject.toml --mc-type library --output-reproducible --output-file artifacts/trustweave.cdx.json
```

Run the example workflow before proposing a change:

```bash
rm -rf artifacts
trustweave scan --manifest examples/support-agent.manifest.json --policy policies/default-policy.json --output-dir artifacts
trustweave test --policy policies/default-policy.json --scenarios scenarios/default-scenarios.json --output-dir artifacts
trustweave test --policy policies/default-policy.json --scenarios scenarios/adversarial-scenarios.json --output-dir artifacts/adversarial
trustweave explain --scenarios scenarios/adversarial-scenarios.json --scenario-id TW-ADV-001
trustweave mcp-import --tool-list examples/mcp-tools/support-tools-list.json --output-dir artifacts/mcp-inventory
trustweave attest --source-revision contributor-check --output-dir artifacts
trustweave report --output-dir artifacts
trustweave verify --attestation artifacts/attestation.json
trustweave policy-check --policy policies/default-policy.json --output-dir artifacts
trustweave trace-review \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --trace examples/traces/clear-support-trace.json \
  --output-dir artifacts/trace-clear \
  --exit-on-review
trustweave mcp-profile-check \
  --manifest examples/support-agent.manifest.json \
  --profile examples/mcp-profiles/clear-support-profile.json \
  --output-dir artifacts/mcp-clear \
  --exit-on-review
```

## Adding a scenario

A scenario is an assertion over abstract labels. It must not contain an exploit payload or invoke a real tool. Add the scenario to a versioned scenario pack and cover it with a positive, negative, or boundary test as appropriate. A new entry in `scenarios/adversarial-scenarios.json` must also have a unique `TW-ADV-*` identifier, a concise rationale, and at least one public `https://` taxonomy or standards reference. See [`docs/SCENARIOS.md`](docs/SCENARIOS.md).

| Scenario type | Example | Expected behavior |
|---|---|---|
| Positive control | Trusted input to a read-only action | `allow` |
| Boundary control | Conditional confidential context to an external mock action | `require_approval` |
| Negative control | Untrusted content to an external action | `deny` |

## Pull-request checklist

Before requesting review, confirm the following statements are true.

- [ ] The change is within the documented safety boundaries.
- [ ] The change includes relevant tests or updates existing deterministic expectations.
- [ ] `ruff format --check .`, `ruff check .`, `mypy src`, `bandit -r src/trustweave -q`, `pytest` (including the 95% branch-coverage gate), `python scripts/reality_check.py`, `python -m build`, `twine check dist/*`, and `pip-audit -r requirements.txt` pass locally.
- [ ] Generated artifact directories, including `artifacts/` and `*-artifacts/`, are not committed.
- [ ] Documentation and examples describe the actual implemented behavior.
- [ ] Any new schema field includes validation and an explicit default/failure behavior.
- [ ] The change does not add real credentials, personal data, third-party targets, unsafe execution paths, reports that reproduce trace message content/tool arguments, or MCP profiles that contain token-like URI components.

## Governance

The repository owner is currently the published release authority and final decision-maker for releases, schema changes, and security-sensitive contributions. See [GOVERNANCE.md](GOVERNANCE.md) for decision and review cadence, [SECURITY.md](SECURITY.md) for vulnerability reporting, [SUPPORT.md](SUPPORT.md) for public support routing, and [docs/RELEASE.md](docs/RELEASE.md) for the release checklist.
