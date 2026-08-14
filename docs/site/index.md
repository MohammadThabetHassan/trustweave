# TrustWeave

TrustWeave is a **local, deterministic security-evidence platform** for teams that need reviewers to reason about declared AI-agent trust boundaries before deployment. It validates supplied manifests, policies, scenarios, trace metadata, and related evidence artifacts. Its outputs make declared decisions, review obligations, provenance limits, and local integrity relationships inspectable without executing an agent or contacting a remote service.

> **Boundary:** TrustWeave analyzes only data supplied to it. It does not discover a runtime topology, execute an agent or tool, load a plugin, connect to MCP, call a model, make a network request, authenticate an identity, sign an artifact, or authorize a deployment.

## Start with a local review

Create a project configuration, produce the coordinated local evidence set, and inspect the generated report. Supply `--generated-at` when reproducible application-layer provenance is required.

```bash
trustweave init --directory .
trustweave --generated-at 2026-08-14T00:00:00+00:00 ci --config trustweave.toml
```

The workflow produces a bundle, synthetic regression results, static policy review, unsigned local attestation, and reviewer-facing report. A successful command means that the supplied declarations were processed according to their local contracts; it is not a runtime-security, deployment, signature, or authorization result.

| Continue reading | Purpose |
|---|---|
| [Concepts](concepts.md) | Explains TrustWeave’s evidence model and its intentional limits. |
| [CLI reference](CLI.md) | Documents command discovery, exit behavior, and output scope. |
| [Rule catalog](RULE_CATALOG.md) | Maps stable built-in review identifiers to their local evidence scope. |
| [Schema catalog](SCHEMAS.md) | Lists packaged schemas and the deterministic discovery command. |
| [Provenance design](PROVENANCE.md) | Separates current unsigned local integrity from future owner-authorized signing. |

## Verify the repository

The project quality gate is local and deterministic:

```bash
ruff format --check . && ruff check . && mypy src && bandit -r src/trustweave -q && pytest && python scripts/reality_check.py
```

The test suite enforces **95% branch coverage**. The repository reality check validates generated artifacts against published schemas, parser-derived CLI coverage, packaged schema resources from an isolated wheel, and repository-controlled documentation and integration wiring.

The complete source documentation, ADRs, and maintainer materials remain versioned in the [repository documentation directory](https://github.com/MohammadThabetHassan/trustweave/tree/main/docs).
