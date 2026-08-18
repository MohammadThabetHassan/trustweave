# Configuration

`trustweave init` writes a starter `trustweave.toml` in an explicitly selected directory and refuses to overwrite an existing file. Configuration is strict, local-only TOML under `[tool.trustweave]`; it does not support remote includes, secret fields, interpolation, executable values, or network access.

```bash
trustweave init --directory .
trustweave config validate --config trustweave.toml
trustweave config show --config trustweave.toml
```

`config validate` reads and validates an explicit local TOML file without changing it. `config show` emits the validated values as deterministic JSON. When a command permits configuration discovery, TrustWeave searches only a bounded number of local parent directories and resolves relative paths from the configuration file’s directory.

## Accepted fields

| Field | Type | Local purpose |
|---|---|---|
| `manifest`, `policy`, `scenarios` | non-empty path string | Declared manifest, deterministic policy, and synthetic scenario inputs. |
| `baseline_bundle`, `candidate_bundle` | non-empty path string | Versioned local bundle inputs for the `diff` stage. Both v1alpha1 and v1alpha2 bundles are compared through the current diff contract. |
| `trace`, `mcp_profile`, `chain_manifest` | non-empty path string | Pre-recorded trace metadata, supplied MCP profile metadata, and declared chain graph inputs. |
| `risk_baseline`, `suppressions` | non-empty path string | Explicit v1alpha2 risk-decision documents. |
| `output_dir`, `sarif_output` | non-empty path string | Local publication destinations. Relative output and SARIF paths are checked for safe containment before artifact creation. |
| `failure_threshold` | `critical`, `high`, `medium`, `low`, `info`, `review`, or `none` | CI failure gate. `review` means any active local risk finding. |
| `enabled_stages` | non-empty unique list | Selects bounded local CI stages. |
| `reproducible` | boolean | Requests deterministic staged-CI provenance behavior. |

The supported stage names are `validate`, `scan`, `scenarios`, `policy_review`, `policy_coverage`, `diff`, `trace_review`, `mcp_profile_review`, `chain_review`, `risk`, `sarif`, `attestation`, `report`, and `summary`.

```toml
[tool.trustweave]
manifest = "examples/support-agent.manifest.json"
policy = "policies/default-policy.json"
scenarios = "scenarios/default-scenarios.json"
baseline_bundle = "artifacts/baseline/agent-security-bundle.json"
candidate_bundle = "artifacts/candidate/agent-security-bundle.json"
output_dir = "artifacts"
sarif_output = "artifacts/trustweave.sarif"
failure_threshold = "review"
enabled_stages = ["validate", "scan", "scenarios", "policy_review", "diff", "risk", "sarif", "attestation", "report", "summary"]
reproducible = true
```

## Validate-stage behavior

The `validate` stage invokes the authoritative typed parsers before any output directory preparation or artifact publication. It semantically validates configured manifests, policies, scenarios, chain manifests, traces, MCP profiles, risk decisions, and both bundle inputs. It also validates output-directory and SARIF containment, rejecting absolute or escaping relative paths and symlink escapes. A failed semantic validation leaves pre-existing output artifacts untouched.

> Configuration selects local evidence inputs and outputs. It does not authenticate a policy, authorize an action, execute a tool, enforce a runtime control, or establish that a declared system is secure.
