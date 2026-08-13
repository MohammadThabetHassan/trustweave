# Public Python API

TrustWeave exposes a small, typed, data-only public surface through `trustweave.api`. Downstream integrations should import from that module rather than reaching into internal modules. The distributed `py.typed` marker remains part of the wheel contract.

| Public service | Purpose |
|---|---|
| `parse_manifest`, `parse_policy` | Validate already-loaded local declarations into immutable models. |
| `evaluate_flow`, `evaluate_manifest`, `build_bundle` | Apply deterministic policy rules to declared data. |
| `review_policy`, `review_declared_chains`, `diff_bundles` | Produce local review evidence from supplied declarations or artifacts. |
| `normalize_findings`, `review_risks` | Normalize supported local review artifacts and apply expiry-enforced reviewer decisions. |
| `ValidationError`, `InputOutputError` | Stable expected-error contract for invalid input and safe local I/O boundaries. |

The public services do not read files, inspect environment secrets, connect to a network, discover or load third-party plugins, execute an agent or tool, or contact a clock. Callers provide already-loaded inputs and any required provenance timestamp explicitly. API output remains design-time evidence, not runtime enforcement or a deployed-system security conclusion.

New rule packs, taxonomies, mappings, and reporting templates should remain data-only and be supplied explicitly. TrustWeave intentionally does not auto-discover or execute installed Python plugins.
