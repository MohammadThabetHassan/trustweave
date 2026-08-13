# Security Policy

## Supported versions

TrustWeave is pre-release software. The `main` branch is the only currently supported development line until a versioned release policy is published.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability. For the private repository, report it directly to the repository owner through GitHub’s private security advisory workflow when enabled, or through a private message to the authorized maintainer.

A useful report includes the affected commit or version, a concise description of the security impact, safe reproduction steps using synthetic data only, expected and observed behavior, and a proposed mitigation if available.

## Safe reporting boundary

Do not submit real credentials, personal data, destructive payloads, malware, instructions for targeting third parties, or proof-of-concept steps that create external side effects. TrustWeave is a local declarative tool; reports should use harmless manifest and policy examples whenever possible.

## Response process

The maintainer should acknowledge a valid report, assess affected versions and scope, prepare a fix with regression coverage, verify the fix locally and in hosted CI, and publish a concise advisory or changelog entry after remediation. Public disclosure timing should balance contributor coordination and user safety.

## Security design limits

TrustWeave v0.1 does not execute tools, configurations, or network traffic. It produces local evidence and does not provide external signing, deployment enforcement, vulnerability scanning, or a guarantee that an agent system is secure. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for complete scope boundaries.
