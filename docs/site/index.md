# TrustWeave

TrustWeave reviews the security configuration of AI agents before deployment. It reads the
declarations a team supplies (agent manifests, policies, synthetic scenarios, trace metadata and
MCP tool snapshots) and reports which inputs can reach which tools, which flows the policy allows,
denies or sends for approval, and what changed between two versions. Everything runs locally and
deterministically.

> **Scope.** TrustWeave analyzes only the files it is given. It does not run an agent or a tool,
> contact a model or an MCP server, or make network requests. Its attestations are unsigned local
> integrity records, not signatures or deployment approvals.

## Start with a local review

Create a project configuration, then produce the full local evidence set and its report. Pass
`--generated-at` when the output must be reproducible byte for byte.

```bash
trustweave init --directory .
trustweave --generated-at 2026-08-14T00:00:00+00:00 ci --config trustweave.toml
```

The run writes a bundle, synthetic regression results, a static policy review, an unsigned local
attestation and a report for the reviewer. A successful run means the declarations were processed
under their contracts; it is not a statement about the security of a deployed system.

| Continue reading | Purpose |
|---|---|
| [Concepts](concepts.md) | The evidence model and its limits. |
| [CLI reference](CLI.md) | Command discovery, exit codes and output scope. |
| [Rule catalog](RULE_CATALOG.md) | The stable rule identifiers and what each one reviews. |
| [Schema catalog](SCHEMAS.md) | The packaged schemas and the command that lists them. |
| [Provenance design](PROVENANCE.md) | Today's unsigned integrity records and the planned signing path. |

## Verify the repository

The full quality gate runs locally:

```bash
ruff format --check . && ruff check . && mypy src && bandit -r src/trustweave -q && pytest && python scripts/reality_check.py
```

The test suite enforces **95% branch coverage**. The reality check validates generated artifacts
against the published schemas, compares CLI coverage with the argument parser, confirms the
packaged schemas from an isolated wheel install, and checks the documentation and integration
wiring.

The complete documentation, including the architecture decision records and maintainer material,
is in the [repository's docs directory](https://github.com/MohammadThabetHassan/trustweave/tree/main/docs).
