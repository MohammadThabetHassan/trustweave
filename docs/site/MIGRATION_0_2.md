# Migrating to 0.2.1

TrustWeave 0.2.1 carries forward the 0.2 hardening while preserving the product boundary: it reviews explicitly supplied declarations and local metadata without executing an agent, model, declared tool, MCP server, plugin, or network operation.

## Upgrade

When 0.2.1 is owner-published, install it into a clean environment and confirm the package contract before using project artifacts:

```shell
python -m pip install --upgrade trustweave==0.2.1
trustweave --help
trustweave schema list
trustweave schema show agent-security-bundle-v1alpha1.schema.json
```

The corrected release target is 0.2.1 and remains owner-controlled until publication succeeds. Annotated v0.2.0 is an immutable unpublished audit tag, was never published to PyPI, and has no GitHub Release. Do not treat these commands as confirmation that either version is already available from a package index.

## Contract changes

| Area | 0.2.1 behavior | Migration action |
| --- | --- | --- |
| Findings | Built-in producers emit bounded, deeply immutable canonical findings validated against `finding/v1alpha1` | Revalidate stored generated artifacts and avoid adding undocumented finding fields |
| Chain manifests | Node kinds use exact field allowlists; ambiguous `output` nodes are not accepted | Replace ambiguous nodes with a documented source, data, tool, sink, approval, or sanitizer role |
| Chain budgets | Paths, states, and edges stop before exceeding the configured budget | Treat `TW-CHAIN-004` as incomplete analysis and review or raise limits deliberately |
| Policy v1alpha2 | Identifier, purpose-tag, classification-bound, capability, and control predicates are validated strictly | Correct invalid taxonomy references, duplicate predicates, unknown controls, and empty intersections |
| Rule guidance | Built-in review rules are registry-backed in JSON, Markdown, SARIF, and the rule catalog | Keep local extensions separate from built-in `TW-*` review identifiers |
| Historical bundle evidence | v1alpha1 bundles must satisfy the authentic historical semantic contract; v1alpha2 remains strict | Preserve valid historical artifacts, regenerate malformed evidence from source inputs, and generate current bundles rather than hand-editing them |
| Risk lifecycle documents | v1alpha2 decisions require valid v3 fingerprints, provenance, duplicate-free entries, and exact expiry behavior | Recreate decisions through the strict local lifecycle workflow; an expiry equal to review time is expired |
| Configuration | `trustweave.toml` is strict, typed, local-only, and bounded in discovery | Rename `baseline` / `candidate` to `baseline_bundle` / `candidate_bundle`; remove unknown fields, remote includes, secret fields, and environment interpolation assumptions |
| CI stages | Fourteen named local stages are supported with declared input dependencies | Select only `validate`, `scan`, `scenarios`, `policy_review`, `policy_coverage`, `diff`, `trace_review`, `mcp_profile_review`, `chain_review`, `risk`, `sarif`, `attestation`, `report`, and `summary` |
| SARIF | Exports use local pinned-schema conformance tests and canonical fingerprint deduplication | Rebuild SARIF from source review artifacts rather than hand-editing exports |

## Verify a migrated project

```shell
trustweave config validate --config trustweave.toml
trustweave --generated-at 2026-08-14T00:00:00+00:00 \
  ci --config trustweave.toml --format json
```

Review every generated `TW-CHAIN-004`, policy coverage, baseline, or suppression result. Baselines and suppressions remain visible reviewer decisions; they are not remediation and do not make a runtime safe.

## Removed and intentionally unsupported behavior

TrustWeave does not preserve an ambiguous chain `output` node. It also does not add automatic uploads, pull-request comments, live endpoint discovery, plugin loading, credential handling, remote policy/schema loading, or runtime enforcement. Those operations remain outside the local deterministic evidence boundary.
