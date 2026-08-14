# Policy review and coverage

TrustWeave evaluates ordered policy rules using one shared predicate model across manifest evaluation, synthetic scenarios, explanations, coverage, and shadow analysis. The first matching rule determines a declared flow’s decision; if none matches, the explicit default decision applies.

```shell
trustweave policy-check \
  --policy policies/default-policy.json \
  --coverage \
  --output-dir artifacts/policy \
  --exit-on-review
```

The command writes local JSON and Markdown review evidence. `--coverage` adds per-rule reachability, possibility, and shadowing information. `--exit-on-review` returns a review status after artifacts have been written; it does not enforce a runtime policy.

| Review condition | Evidence consequence |
| --- | --- |
| Default decision is `allow` | `TW-POL-001` asks a reviewer to inspect unmatched declared paths |
| Earlier rule covers a later rule | `TW-POL-002` reports a first-match shadow; a differing decision also produces `TW-POL-007` |
| Rule requires controls absent from policy declarations | `TW-POL-008` marks it impossible to decide a flow |
| Untrusted flow is allowed to external or sensitive action | `TW-POL-003` requires review of authorization and human-control boundaries |
| High-impact approval lacks required declared bindings or fail-closed intent | `TW-POL-004`, `TW-POL-005`, or `TW-POL-006` prompts review |

Coverage is a deterministic property of supplied policy declarations and the declared taxonomy/control model. It does not prove a deployment presents every possible flow, that an approver exists, or that an approval mechanism validates a real identity.

## Explanations and scenarios

Use synthetic scenarios to make individual rule expectations regression-testable. Use `trustweave why` to emit a local explanation that shows the matching rule or default decision for supplied declared labels. Both use the same predicate semantics as policy review and coverage; neither reads a live request, contacts a model, or executes a tool.
