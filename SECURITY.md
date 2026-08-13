# Security Policy

## Supported versions

TrustWeave `0.1.1` is the current released package line. Security fixes are assessed against the latest published version and the current `main` branch. The project’s manifest, policy, trace, MCP-profile, and generated-artifact contracts remain explicitly documented as `v1alpha1`; compatibility expectations are described in [docs/SCHEMA_AND_COMPATIBILITY.md](docs/SCHEMA_AND_COMPATIBILITY.md).

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability. When private vulnerability reporting is available on the repository, use GitHub’s **Report a vulnerability** flow from the repository’s Security tab. It keeps the report and follow-up discussion private to the reporter and maintainers.

A useful report identifies the affected version or commit, describes the security impact, and provides safe reproduction steps using synthetic data only. Include expected and observed behavior, relevant local configuration, and a proposed mitigation if available. Do not include secrets or data that a maintainer should not retain.

## Safe reporting boundary

Do not submit real credentials, personal data, destructive payloads, malware, instructions for targeting third parties, or proof-of-concept steps that create external side effects. TrustWeave is a local declarative tool; reports should use harmless manifests, policies, scenarios, trace metadata, and MCP metadata profiles whenever possible.

A report about TrustWeave should distinguish a suspected defect in **this project** from a concern about a deployed agent, MCP server, or third-party system. TrustWeave does not operate those systems and cannot safely receive their credentials, raw trace content, tool arguments, customer records, or incident data.

## Response process

The maintainer will acknowledge a valid private report, assess affected versions and scope, prepare a fix with regression coverage, verify the fix locally and in hosted CI, and publish a concise advisory or changelog entry after remediation when appropriate. Disclosure timing should balance reporter coordination, user safety, and the availability of a tested fix.

Maintainers aim to acknowledge a valid private report within **seven calendar days** and provide a status update after triage. This is a best-effort communication objective, not a guarantee of remediation timing, availability, or a specific severity classification. Until a broader maintainer group and response rotation are established, the repository owner coordinates private reports. See [GOVERNANCE.md](GOVERNANCE.md) for review ownership and cadence.

## Security design limits

TrustWeave `0.1.1` does not execute tools, configurations, or network traffic. It produces local evidence and does not provide external signing, deployment enforcement, external agent or infrastructure vulnerability scanning, or a guarantee that an agent system is secure.

The repository runs a static source-security scan and a declared dependency audit in CI. Those checks review this Python project and its declared dependency set; they do not scan a contributor’s workstation, a trace-producing system, an MCP server, a deployed agent, or a third-party dependency’s runtime environment. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/QUALITY.md](docs/QUALITY.md) for complete scope boundaries.
