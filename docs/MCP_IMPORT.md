# Local MCP Tools-List Import

`trustweave mcp-import` converts an **already-provided local** MCP `tools/list` snapshot into a normalized review inventory. It is designed for architecture review before an integration is accepted or connected—not for server discovery, transport testing, or runtime enforcement.

```bash
trustweave mcp-import \
  --tool-list examples/mcp-tools/support-tools-list.json \
  --output-dir artifacts/mcp-inventory
```

The command writes `mcp-tool-inventory.json`. It is deterministic: tools are sorted by name and the output contains no fetch timestamp, discovered endpoint, token, or tool result.

## Accepted local snapshot shape

The importer expects a top-level `tools` list. Every tool needs a unique nonblank `name` and an object-valued `inputSchema`. `description` is optional. If provided, it accepts and validates the following annotation fields:

| Field | Accepted type | Meaning in the inventory |
|---|---:|---|
| `title` | String | Display metadata only. |
| `readOnlyHint` | Boolean | Review metadata only. |
| `destructiveHint` | Boolean | Review metadata only. |
| `idempotentHint` | Boolean | Review metadata only. |
| `openWorldHint` | Boolean | Review metadata only. |

MCP describes tools using a name, description, input schema, and optional annotations.[1] It also states that clients must consider annotations untrusted unless they come from trusted servers.[1] TrustWeave therefore preserves selected hints for reviewer visibility but never uses them to infer an `action_class`, grant authorization, or override the declared Agent Security Manifest and policy.

## Reviewer-required manifest scaffold

After creating an inventory, generate a non-authorizing draft:

```bash
trustweave mcp-scaffold --inventory artifacts/mcp-inventory/mcp-tool-inventory.json --output-dir artifacts
```

The command writes `mcp-manifest-scaffold.json`. Its `manifest_draft` is deliberately **not** a valid Agent Security Manifest: every imported tool is marked `REVIEW_REQUIRED`, and sources and flows are empty. A reviewer must set action classes, capabilities, sources, flows, and deterministic policy before running a normal TrustWeave scan. The scaffold makes no server connection and never infers authorization from names, schemas, descriptions, or annotations.

## Output contract

| Field | Meaning |
|---|---|
| `schema_version` | `trustweave.dev/mcp-tool-inventory/v1alpha1`. |
| `tools` | Stable sorted normalized local metadata for each declared input tool. |
| `summary.tool_count` | Number of unique local tools accepted. |
| `summary.tools_with_annotations` | Number of tools containing at least one accepted annotation. |
| `limits` | Explicit statements that no connection, authentication, invocation, authorization inference, or security verdict occurred. |

This inventory is intentionally **not** an Agent Security Manifest. A reviewer must still classify each tool’s action class and define source-to-tool flows in the manifest. Existing `mcp-profile-check` remains the separate command for comparing a manually declared profile with manifest mappings.

## Rejections and limits

The importer rejects a missing `tools` list, a non-object tool, a blank or duplicate tool name, a non-object `inputSchema`, or a selected annotation with the wrong type. It does not validate the full semantics of a JSON Schema and it does not resolve references, retrieve external documents, parse a transport configuration, connect to an MCP server, exchange credentials, or invoke a tool.

> The local file is evidence supplied by a reviewer. It is not proof that a remote MCP server exposes the same tools, that its metadata is trustworthy, or that it enforces access control.

## Reference

[1]: https://modelcontextprotocol.io/specification/2025-03-26/server/tools "MCP tools specification (2025-03-26)"
