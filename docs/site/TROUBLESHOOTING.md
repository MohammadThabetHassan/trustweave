# Troubleshooting and known limitations

TrustWeave only reads the files you give it, so most failures come down to the input: keep the failing command output handy, fix the declaration, and re-run. Don't edit generated artifacts to make a finding go away — that's the one thing the evidence chain is designed to catch.

| Symptom | Likely cause | Safe next step |
| --- | --- | --- |
| Exit code `2` | Invalid command syntax, schema, policy, or provenance field | Run `trustweave --help`, then use `trustweave schema list` and `trustweave schema show <name>` to inspect the accepted local contract |
| Exit code `3` | Input or output cannot be safely accessed | Check the path, permissions, encoding, and that the input is not a symbolic link |
| A flow uses the default decision | No ordered rule matched all declared predicates | Use `trustweave why` or policy explanation output; then add or correct a reviewed rule rather than changing a generated bundle |
| Policy review reports a conflict, redundancy, or impossible rule | Ordered predicates overlap or cannot match | Inspect rule order and predicates with [policy versions and controls](POLICY_VERSIONS.md), then make the intended decision explicit |
| Chain review emits `TW-CHAIN-004` | A traversal budget prevented exhaustive analysis | Review the partial result and limitation; only raise a budget after reviewing the declared graph's expected scale |
| Risk record is active after an exception was recorded | The baseline or suppression is expired or does not match the exact fingerprint | Renew only through a reviewer-visible change with an explicit reason and new bounded expiry, or resolve the source finding |
| Attestation verification fails | Referenced local bytes or stable payload links differ | Recreate artifacts from the reviewed inputs; an unsigned local attestation does not identify who created a file |

## Known limitations

TrustWeave is a declarative architecture-review and synthetic-regression tool. It does not execute agents or tools, connect to services, discover endpoints, read credentials, load plugins, evaluate configuration code, upload artifacts, post comments, sign statements, or publish releases. It does not inspect data content, prove runtime approval or sanitization, detect real-world prompt injection, authenticate unsigned artifacts, establish evidence origin, or certify a deployed system.

A policy result describes the supplied manifest and policy; a chain result describes the supplied graph within its recorded budgets; a risk record organizes supplied review findings and expiry decisions. Each result remains evidence for human review, not an automated authorization, remediation, deployment, or security conclusion.

For the complete boundary, read the [threat model](THREAT_MODEL.md). If you have a reproducible defect in local parsing or deterministic evaluation, report it through the repository process without including credentials, personal data, third-party exploit chains, or harmful operational instructions. Follow the repository security policy for potential vulnerabilities.
