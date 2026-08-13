# Contributing to TrustWeave

Thank you for helping improve TrustWeave. The project welcomes contributions that make agent-security review more reproducible, understandable, and safe.

## Contribution principles

1. **Preserve the non-executing core.** Manifests and scenarios are data, not executable tool configurations. Do not add hidden command execution, network calls, credential discovery, or model calls to the core workflow.
2. **Add evidence with behavior.** A new policy feature, finding type, or scenario must include at least one deterministic test and explicit limits.
3. **Keep safety claims narrow.** Do not describe TrustWeave as preventing all prompt injection, proving a system secure, or replacing a security assessment.
4. **Use synthetic examples.** Tests and demonstration data must not contain real customer records, secrets, tokens, or third-party targets.
5. **Keep contracts stable.** Schema changes require a documented migration path and compatibility test.

## Local development

```bash
python -m pip install -e .
python -m pip install pytest ruff mypy PyYAML

ruff format --check .
ruff check .
mypy src
pytest
```

Run the example workflow before proposing a change:

```bash
rm -rf artifacts
trustweave scan --manifest examples/support-agent.manifest.json --policy policies/default-policy.json --output-dir artifacts
trustweave test --policy policies/default-policy.json --scenarios scenarios/default-scenarios.json --output-dir artifacts
trustweave attest --source-revision contributor-check --output-dir artifacts
trustweave report --output-dir artifacts
trustweave verify --attestation artifacts/attestation.json
```

## Adding a scenario

A scenario is an assertion over abstract labels. It must not contain an exploit payload or invoke a real tool. Add the scenario to a versioned scenario pack and cover it with a positive, negative, or boundary test as appropriate.

| Scenario type | Example | Expected behavior |
|---|---|---|
| Positive control | Trusted input to a read-only action | `allow` |
| Boundary control | Conditional confidential context to an external mock action | `require_approval` |
| Negative control | Untrusted content to an external action | `deny` |

## Pull-request checklist

Before requesting review, confirm the following statements are true.

- [ ] The change is within the documented safety boundaries.
- [ ] The change includes relevant tests or updates existing deterministic expectations.
- [ ] `ruff format --check .`, `ruff check .`, `mypy src`, and `pytest` pass locally.
- [ ] Generated `artifacts/` files are not committed.
- [ ] Documentation and examples describe the actual implemented behavior.
- [ ] Any new schema field includes validation and an explicit default/failure behavior.
- [ ] The change does not add real credentials, personal data, third-party targets, or unsafe execution paths.

## Governance

Until a published maintainer group is established, repository owners make final decisions on releases, schema changes, and security-sensitive contributions. See [SECURITY.md](SECURITY.md) for vulnerability reporting and [docs/RELEASE.md](docs/RELEASE.md) for the release checklist.
