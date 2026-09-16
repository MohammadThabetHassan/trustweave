# Declared chain model and budgets

Chain review analyzes an optional local `chain-manifest/v1alpha1` graph. It evaluates only nodes and directed edges that a reviewer explicitly supplies. It does not execute an agent, discover a topology, call a tool, inspect a live endpoint, or infer behavior from names or descriptions.

| Node role | Required declared property |
| --- | --- |
| `source` | Trust label; may declare an initial classification |
| `data` | Classification |
| `tool` or `sink` | Action class |
| `approval` | Fail-closed state |
| `sanitizer` | Unique covered classifications |

Each role rejects incompatible fields. The ambiguous `output` role is intentionally unsupported.

```shell
trustweave chain-check \
  --input examples/chains/safe-sanitized-external.chain.json \
  --output-dir artifacts/chain
```

The deterministic traversal starts only from declared untrusted sources and records ordered node identities for declared paths that reach sensitive data and an external action. Distinct routes remain distinct even when their propagated metadata is identical. A declared external action is recorded as a path and the traversal continues through that node's own declared successors, so data a declared external call brings back is reviewed rather than dropped; a successor already on the current path is never followed twice, so a declared cycle cannot enumerate itself.

A classification propagates only when the graph treats it as sensitive. That set defaults to `confidential` and `restricted`, and a graph may declare its own `classification_taxonomy` and `sensitive_classifications` instead. Propagation compares exact strings, so a value that only looks like a declared one — `Restricted` against `restricted` — is refused rather than silently propagating nothing, and a term outside the taxonomy is named in the review's `warnings` list.

## Controls and findings

A fail-closed approval covers only the sensitive classifications present at the approval node. Data acquired later needs a later declared approval. A sanitizer covers only classifications it explicitly lists. `TW-CHAIN-001` identifies an explicit untrusted-sensitive-external path, `TW-CHAIN-002` identifies missing scoped fail-closed approval, and `TW-CHAIN-003` identifies incomplete declared sanitizer coverage.

## Hard budgets

Chain analysis bounds nodes, paths, edges, depth, and explored states. Each budget is checked **before** the counter is increased, so recorded results never exceed the configured limit. When a limit prevents exhaustive review, TrustWeave emits `TW-CHAIN-004` and preserves partial evidence with an explicit limitation.

> A clear chain review describes only the supplied graph within its configured budgets. It is not proof that a deployed system has no other path, runtime approval, or effective sanitization control.
