# Offline Trace Review

## Purpose

`trustweave trace-review` compares a **local, pre-recorded structured trace** with a declared Agent Security Bundle input: an agent manifest and a deterministic policy. It helps a reviewer ask a bounded question:

> Did the recorded tool-call metadata match the sources, tools, flows, and deterministic policy that this repository declares?

The command is designed for CI evidence, local regression fixtures, and review of a trace export that a separate system has already produced. It does not connect to a target, load an adapter, execute an agent, call a model, send a tool request, or perform a network operation.

## Use it safely

The trace reviewer treats every trace as **data**. It never evaluates message text as an instruction and never executes tool arguments. It intentionally excludes both message contents and tool arguments from its JSON observation set and Markdown report.

Do not place real secrets, personal data, credentials, or unredacted production content in a TrustWeave trace fixture. The parser does not reproduce those fields, but a repository should still retain only synthetic or appropriately governed evidence.

## Trace contract

Trace files use `trustweave.dev/trace/v1alpha1` and contain three lists.

```json
{
  "schema_version": "trustweave.dev/trace/v1alpha1",
  "messages": [],
  "tool_calls": [],
  "events": []
}
```

The machine-readable structural contract is [`schemas/trace.schema.json`](../schemas/trace.schema.json). The Python validator is authoritative at runtime.

### `messages`

`messages` must be a list. TrustWeave records only the **count** in its review summary. It does not inspect or emit a message’s `role`, `content`, or additional fields.

### `tool_calls`

Every observed tool call must include the declared `source` name and exactly one unambiguous tool name. TrustWeave accepts `name`, `tool`, or `tool_name` for compatibility with common trace normalizations. If more than one name field appears, all provided names must match.

```json
{
  "name": "send_mock_email",
  "source": "knowledge_base_document",
  "arguments": {
    "recipient": "synthetic@example.invalid"
  }
}
```

The `arguments` object is allowed in the trace but is never copied into the review artifact or report.

### `events`

Every event must have a non-empty `type`. The reviewer counts `untrusted_context_received` events because they are useful trust-boundary evidence. It does not infer intent from event fields, message text, tool output, or model behavior.

```json
{
  "type": "untrusted_context_received",
  "policy": "synthetic test event"
}
```

## Findings

| Identifier | Review condition | Meaning |
|---|---|---|
| `TW-TRACE-001` | The observed call names an undeclared source. | The trace contains a source absent from the manifest. Review whether the manifest is incomplete, the trace is wrong, or the integration changed. |
| `TW-TRACE-002` | The observed call names an undeclared tool. | The trace contains a tool absent from the manifest. Review whether an undeclared capability exists or normalization needs correction. |
| `TW-TRACE-003` | The observed source-to-tool pair is not a declared flow. | Both declarations exist, but the specific route was not approved in the manifest. |
| `TW-TRACE-004` | A declared observed flow evaluates to `deny`. | The trace records a call that the local policy denies. Review enforcement, trace origin, and intended configuration. |
| `TW-TRACE-005` | A declared observed flow evaluates to `require_approval`. | The trace records a call that needs an approval control under the local policy. Review whether evidence of approval exists in the system that produced the trace. |

A finding does not prove malicious behavior, compromise, policy enforcement failure, or a vulnerability. It means that a reviewer should compare the local trace evidence with the declared architecture and operational context.

## Worked examples

### Clear fixture

```bash
trustweave trace-review \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --trace examples/traces/clear-support-trace.json \
  --output-dir artifacts/trace-clear \
  --exit-on-review
```

The clear fixture records a trusted `customer_request` using the declared read-only `search_knowledge_base` tool. It produces no findings and exits `0`.

### Review-required fixture

```bash
trustweave trace-review \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --trace examples/traces/review-required-support-trace.json \
  --output-dir artifacts/trace-review \
  --exit-on-review
```

This synthetic fixture records `untrusted_context_received` and a call from `knowledge_base_document` to `send_mock_email`. The default reference policy denies that declared route. The command writes artifacts and exits `1` because `--exit-on-review` is present.

## CI usage

Use `--exit-on-review` only when every finding should block the workflow pending review. In a repository with an expected review-required fixture, assert that the command returns `1` rather than treating it as a passing gate.

```bash
set +e
trustweave trace-review \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --trace examples/traces/review-required-support-trace.json \
  --output-dir artifacts/trace-review \
  --exit-on-review
review_exit=$?
set -e

test "$review_exit" -eq 1
grep -q 'TW-TRACE-004' artifacts/trace-review/trace-review.json
```

## Evidence limits

Trace review makes no claim that a trace is authentic, complete, tamper-proof, or representative of a deployed agent. It does not verify an actor identity, inspect authorization tokens, establish that an approval occurred, analyze message semantics, or replace an incident investigation. Pair it with the [Threat Model](THREAT_MODEL.md), [Quality Evidence Guide](QUALITY.md), and the trace-producing system’s own provenance controls.
