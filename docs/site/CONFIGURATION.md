# Configuration

A `trustweave.toml` file selects **local declaration inputs and local artifact paths**. It is not a plugin, script, secret store, remote include mechanism, or runtime policy-enforcement channel.

Create a starter file without overwriting an existing one:

```shell
trustweave init --directory .
trustweave config validate --config trustweave.toml
trustweave config show --config trustweave.toml
```

The configuration loader accepts a strict `[tool.trustweave]` table. Relative paths resolve from the directory containing the configuration file. Explicit command-line values take precedence over configured values; controlled upward discovery can locate the nearest local configuration when no explicit file is provided.

| Field | Local purpose |
| --- | --- |
| `manifest`, `policy`, `scenarios` | Declared architecture, deterministic policy, and synthetic scenario inputs |
| `chain_manifest`, `trace`, `mcp_profile` | Optional supplied local metadata reviews |
| `baseline`, `candidate`, `risk_baseline`, `suppressions` | Optional local comparison and reviewer-decision artifacts |
| `output_dir`, `sarif_output` | Explicit local artifact destinations |
| `failure_threshold`, `enabled_stages`, `reproducible` | Deterministic local coordinator behavior |

Unknown fields are rejected. Configuration never interpolates environment values, reads credentials, loads remote material, evaluates code, or causes an agent, model, tool, MCP server, or network request to run.

## Staged local workflow

```shell
trustweave --generated-at 2026-08-14T00:00:00+00:00 \
  ci --config trustweave.toml --format markdown
```

The coordinator resolves one timestamp for the run, stages artifacts in a temporary directory, and publishes the completed local output directory atomically. It supports scan, synthetic scenarios, policy review and coverage, optional chain review, SARIF, attestation, report, and deterministic summary stages. Unsupported configured stages fail closed.

> A successful local review describes only the supplied declarations and local metadata. It does not prove deployed behavior, authenticate a declaration, authorize an action, or establish operational security.
