# Support

TrustWeave is a local, deterministic review tool. The most effective support request starts with the smallest safe local example that demonstrates the question or defect.

| Need | Start here |
| --- | --- |
| Install, choose a workflow, or understand what a result means | [README.md](README.md) and the [documentation map](README.md#documentation-map). |
| Exact command inputs, outputs, exit codes, or errors | [CLI reference](docs/CLI_REFERENCE.md). |
| Understand safety limits and supported evidence claims | [Product contract](docs/PRODUCT_CONTRACT.md), [threat model](docs/THREAT_MODEL.md), and [quality guide](docs/QUALITY.md). |
| Report a reproducible defect in TrustWeave | Use the repository’s **Bug report** issue form with synthetic, minimized input. |
| Propose a bounded improvement | Use the **Bounded feature request** issue form and connect it to a reviewer decision, deterministic evidence, and the safety boundary. |
| Report a suspected vulnerability | Do **not** open a public issue. Follow [SECURITY.md](SECURITY.md). |

## What to include

For a public bug report, include the TrustWeave version or commit, Python and operating-system version, expected and observed behavior, and a minimal safe reproduction. Use synthetic manifests, policies, scenarios, trace metadata, and MCP profile data only.

Please do not publish credentials, personal data, customer data, raw trace content, tool arguments, destructive payloads, third-party targets, or vulnerability details in a public issue. TrustWeave does not operate external agents, MCP servers, or customer systems and cannot safely support requests that require accessing them.

## Maintainer capacity

TrustWeave is currently maintained by its repository owner. The project welcomes well-scoped, evidence-backed contributions, but it does not promise real-time support, custom integrations, security consulting, or a managed agent-security service.
