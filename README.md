<p align="center">
  <img src="assets/trustweave-mark.svg" width="104" alt="TrustWeave woven-shield product mark">
</p>

<h1 align="center">TrustWeave</h1>

<p align="center">
  <strong>Review your AI agent's security configuration before you deploy it.</strong><br>
  Local, deterministic, and fast — no agent runs, no network calls, no data leaves your machine.
</p>

<p align="center">
  <a href="https://pypi.org/project/trustweave/"><img src="https://img.shields.io/pypi/v/trustweave?label=PyPI&color=0F766E" alt="PyPI version"></a>
  <a href="https://github.com/MohammadThabetHassan/trustweave/actions/workflows/ci.yml"><img src="https://github.com/MohammadThabetHassan/trustweave/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://pypi.org/project/trustweave/"><img src="https://img.shields.io/pypi/pyversions/trustweave?color=2563EB" alt="Supported Python versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-4F46E5" alt="Apache-2.0 license"></a>
</p>

<p align="center">
  <a href="#try-it-in-two-minutes">Try it</a> ·
  <a href="#why">Why</a> ·
  <a href="docs/site/INTEGRATIONS.md">Integration routes</a> ·
  <a href="docs/CLI_REFERENCE.md">CLI reference</a> ·
  <a href="#docs">Docs</a> ·
  <a href="SECURITY.md">Security</a>
</p>

---

## Try it in two minutes

```bash
python -m pip install --upgrade trustweave
```

Point `scan` at a declared agent manifest and a policy:

```bash
git clone https://github.com/MohammadThabetHassan/trustweave.git
cd trustweave && pip install -e .

trustweave scan \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --output-dir artifacts
```

You get a decision for every declared trust-boundary path — which sources may use which tools, and under what conditions:

| Source | Trust | Tool | Decision |
|---|---|---|---|
| customer_request | trusted | search_knowledge_base | **allow** |
| customer_record | conditional | send_mock_email | **require_approval** |
| customer_request | trusted | lookup_customer_record | **deny** |
| knowledge_base_document | untrusted | send_mock_email | **deny** |

Then check the policy against synthetic scenarios, and produce a report a human reviewer can actually read:

```bash
trustweave test \
  --policy policies/default-policy.json \
  --scenarios scenarios/default-scenarios.json \
  --output-dir artifacts

trustweave attest --source-revision local --output-dir artifacts
trustweave report --output-dir artifacts

# Confirm the evidence files haven't changed since the attestation:
trustweave verify \
  --attestation artifacts/attestation.json \
  --bundle artifacts/agent-security-bundle.json \
  --test-results artifacts/security-test-results.json
```

Everything above reads only checked-in local files. Inspect any command with `trustweave --help` or `python -m trustweave --help`.

Under the hood, bundles use the `trustweave.dev/bundle/v1alpha2` contract and risk decisions carry canonical `trustweave/fingerprint/v3` identities, so evidence stays comparable across runs. Note that supplying the bundle and test-result paths to `verify` checks those exact local bytes; running `verify` with only the attestation checks only the statement’s internal consistency.

## Why

A config change can open a new sensitive path — an untrusted source reaching an external tool — without touching application code. TrustWeave catches that at review time:

- **`scan`** maps every declared flow (source → tool → action) and applies your policy deterministically.
- **`diff`** shows exactly what a candidate config changes versus your baseline.
- **`test`** replays safe synthetic scenarios so policy regressions fail in CI, not in production.
- **`trace-review`** and **`mcp-profile-check`** flag where recorded metadata drifts from the declaration.

One honest boundary: TrustWeave reviews *declarations* — manifests, policies, saved snapshots. It never executes agents, calls tools, contacts servers, or tells you a deployed agent is secure. It gives you stable evidence to review; the judgment stays with you.

## Pick your entry point

| You already have… | Start here |
| --- | --- |
| A LangGraph, OpenAI Agents, or CrewAI export | [Framework import](docs/FRAMEWORK_IMPORT.md) |
| A saved MCP `tools/list` snapshot | [MCP import](docs/MCP_IMPORT.md) |
| A CI pipeline | [Local CI integration](docs/CI_INTEGRATIONS.md) |
| Nothing yet — just curious | The quickstart above |

The [Developer integration routes](docs/site/INTEGRATIONS.md) page has copy-paste commands for each path.

<a name="docs"></a>
## Docs

**Using it:** [Installation](docs/site/INSTALLATION.md) · [CLI reference](docs/CLI_REFERENCE.md) · [Rule catalog](docs/site/RULE_CATALOG.md) · [Troubleshooting](docs/site/TROUBLESHOOTING.md) · [Configuration](docs/CONFIGURATION.md)

**Understanding it:** [Concepts](docs/site/concepts.md) · [How it compares](docs/site/COMPARISON.md) · [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Product contract](docs/PRODUCT_CONTRACT.md) · [Reviewer workflow](docs/REVIEWER_WORKFLOW.md)

**Trusting it:** [Quality & test gates](docs/QUALITY.md) · [Mutation testing record](docs/MUTATION_TESTING.md) · [Supply-chain evidence](docs/SUPPLY_CHAIN.md) · [Reproducibility](docs/REPRODUCIBILITY.md) · [Evaluation framework](docs/evaluation/EVALUATION_CHARTER.md)

<details>
<summary><strong>Everything else (schemas, risk, release records)</strong></summary>

- [Schema and compatibility policy](docs/SCHEMA_AND_COMPATIBILITY.md)
- [Local risk management](docs/RISK_MANAGEMENT.md) — fingerprints, baselines, suppressions
- [Control traceability](docs/CONTROL_TRACEABILITY.md)
- [Golden deterministic evidence](docs/GOLDEN_EVIDENCE.md)
- [Resource bounds](docs/RESOURCE_BOUNDS.md)
- [Release guide](docs/RELEASE.md) and [release history](https://github.com/MohammadThabetHassan/trustweave/releases)
- Historical release checklists, migration guides, and audit records live under `docs/archive/` (added in this overhaul)

</details>

## Quality, briefly

95% branch coverage enforced in CI · 98.44% mutation score across twelve core modules, all survivors triaged · reproducible wheels with fixed epoch · SBOM + PyPI provenance attestations · zero runtime dependencies. Details in [QUALITY.md](docs/QUALITY.md).

Optional: YAML manifest support via `pip install "trustweave[yaml]"`.

## Contributing

Bug reports and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Questions start at [SUPPORT.md](SUPPORT.md). Please don't report vulnerabilities in public issues; follow [SECURITY.md](SECURITY.md). Community norms: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md); project decisions: [GOVERNANCE.md](GOVERNANCE.md).

Used TrustWeave on a real agent? A short write-up helps the next team decide — [here's the template](docs/CASE_STUDIES.md).

## License

[Apache License 2.0](LICENSE).
