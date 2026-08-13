# TrustWeave

> **Review agent-security changes like code.** TrustWeave inventories declared agent trust boundaries, evaluates deterministic flow policies, runs safe synthetic regressions, and writes local evidence artifacts for review.

TrustWeave is a **local-first developer tool** for teams adding tools or MCP-style integrations to AI agents. Its initial goal is deliberately narrow: make a security-relevant architecture change visible in CI before it becomes a deployed behavior.

## What the first release does

| Command | Output | What it proves |
|---|---|---|
| `trustweave scan` | Agent Security Bundle | The declared sources, tools, flows, policy decisions, and explicit scope limits for one manifest. |
| `trustweave test` | Synthetic regression results | Whether the local deterministic policy returns the expected decisions for safe synthetic scenarios. |
| `trustweave attest` | Hash-linked local attestation | The integrity relationship among the generated bundle, test results, and stated source revision. |
| `trustweave report` | Markdown evidence report | A review-friendly explanation of declared paths and policy decisions. |
| `trustweave verify` | Verification result | Whether an attestation’s internal hash chain matches its predicate. |

> **Security boundary:** TrustWeave v0.1 does not execute MCP configurations, run agent tools, contact networks, access credentials, call models, scan systems, or act on external data. It analyzes only a local declarative manifest and fixed synthetic scenarios.

## Quick start

TrustWeave currently targets Python 3.11+ and has no required runtime dependencies beyond the standard library for JSON inputs. YAML manifests require the optional `PyYAML` package.

```bash
git clone https://github.com/AbdulrahmanRezki/trustweave.git
cd trustweave
python -m pip install -e .

trustweave scan \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --output-dir artifacts

trustweave test \
  --policy policies/default-policy.json \
  --scenarios scenarios/default-scenarios.json \
  --output-dir artifacts

trustweave attest --source-revision "$(git rev-parse --short HEAD 2>/dev/null || echo local)" --output-dir artifacts
trustweave report --output-dir artifacts
trustweave verify --attestation artifacts/attestation.json
```

The example is a fully synthetic customer-support agent. It declares a safe retrieval path, a confidential-data path that requires approval before a mock external action, and an intentionally unsafe untrusted-content-to-external-action path that the policy denies.

## Expected result

The workflow produces four local artifacts.

```text
artifacts/
├── agent-security-bundle.json
├── security-test-results.json
├── attestation.json
└── report.md
```

The generated report identifies the unsafe declared path and records the deterministic decision without sending a message, reading a real customer record, or invoking an external tool.

## Why TrustWeave

AI agents increasingly connect user requests, retrieved content, tools, and sensitive systems. A model-level safeguard alone is not a deterministic control over what a connected tool can do. TrustWeave focuses on **explicit boundaries**: every source has a trust label, every tool has an action class, every declared flow is reviewed by a visible policy, and every regression scenario documents an expected decision.

The project is designed to complement—not replace—existing components such as authorization engines, policy engines, runtime gateways, security scanners, and observability tools. See [Architecture](docs/ARCHITECTURE.md) and [Product Contract](docs/PRODUCT_CONTRACT.md).

## Repository map

| Path | Purpose |
|---|---|
| `src/trustweave/` | CLI, manifest validation, policy engine, evidence builder, and report renderer. |
| `examples/` | Safe, synthetic reference agent manifests. |
| `policies/` | Deterministic, declarative policy examples. |
| `scenarios/` | Safe synthetic regression assertions. |
| `tests/` | Unit and end-to-end verification. |
| `docs/` | Architecture, threat model, governance, contributor, and release guidance. |
| `.github/workflows/` | Continuous integration and dependency-review workflows. |

## Verification

The core verification command is:

```bash
ruff format --check .
ruff check .
mypy src
pytest
```

The initial repository baseline was verified locally with **Ruff formatting and linting, strict type checking over `src`, six unit/end-to-end tests, and the documented synthetic evidence workflow**. Generated artifacts are excluded from version control and can be regenerated from the checked-in example.

## Scope and non-goals

TrustWeave does not claim to prove that an agent application is secure, stop all prompt injection, replace threat modeling, or perform a penetration test. It is a local developer control that creates visible, repeatable, deterministic evidence for the agent architecture a team explicitly declares.

The future roadmap may include MCP-aware adapters, policy-engine integration, standard attestation formats, framework SDKs, richer evidence linking, and external signing. These capabilities are not present in v0.1 and must not be inferred from this repository.

## Contributing and security

Contributions are welcome once the repository is available to authorized collaborators. Please read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before opening an issue or proposing a change.

## License

TrustWeave is distributed under the [Apache License 2.0](LICENSE).
