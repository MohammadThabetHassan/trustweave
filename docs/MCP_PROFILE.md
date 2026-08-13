# MCP Metadata Profile Review

## Purpose

`trustweave mcp-profile-check` reviews an explicit **local metadata profile** for a Model Context Protocol server against an Agent Security Manifest. It answers a narrow configuration question:

> Does the user-supplied MCP profile map its declared tools consistently to this repository’s manifest, and are the transport and authorization expectations visible for review?

The command does not discover a server, open a transport, retrieve server metadata, negotiate capabilities, perform OAuth, read a token, validate an audience claim, or call an MCP tool. The profile is local declarative input only.

## Why metadata review matters

An agent’s manifest names the tools it is expected to use and their action classes. An MCP integration adds another configuration boundary: a server’s declared transport, a resource identifier, an authorization expectation, and a mapping from server tools to those manifest tools. Making the mapping explicit helps a reviewer catch drift before integration code or a deployment is changed.

TrustWeave does not claim MCP protocol conformance. The profile is a pre-deployment review artifact that complements, rather than replaces, MCP authorization, transport security, identity, and runtime enforcement.

## Profile contract

Profiles use `trustweave.dev/mcp-profile/v1alpha1`. The structural schema is [`schemas/mcp-profile.schema.json`](../schemas/mcp-profile.schema.json); the typed Python validator is authoritative at runtime.

```json
{
  "schema_version": "trustweave.dev/mcp-profile/v1alpha1",
  "name": "synthetic-support-service",
  "transport": "http",
  "resource_uri": "https://mcp.synthetic.invalid/support",
  "authorization_expected": true,
  "tools": [
    {
      "name": "knowledge.search",
      "manifest_tool": "search_knowledge_base",
      "action_class": "read",
      "description": "Synthetic capability mapping."
    }
  ]
}
```

| Field | Requirement | Safety rule |
|---|---|---|
| `name` | Non-empty profile identifier. | It is an identifier only; it does not trigger discovery. |
| `transport` | `http` or `stdio`. | No transport is opened. |
| `resource_uri` | Required for `http`; absolute HTTP(S) URI without credentials, query parameters, or fragments. | It is rendered only as a validated identifier. Tokens and URL query secrets are rejected. |
| `authorization_expected` | Boolean design expectation. | It is not evidence of OAuth support, a valid token, a bound audience, or authorization success. |
| `tools` | Non-empty mappings with a unique MCP name and manifest-tool target. | Every mapping is compared with the manifest; no MCP tool is called. |

## Run a check

```bash
trustweave mcp-profile-check \
  --manifest examples/support-agent.manifest.json \
  --profile examples/mcp-profiles/clear-support-profile.json \
  --output-dir artifacts/mcp-clear \
  --exit-on-review
```

The clear fixture maps two synthetic MCP tools to declared manifest tools with matching action classes and declares that authorization is expected for its HTTP integration.

Run the review-required fixture to test CI gate behavior:

```bash
trustweave mcp-profile-check \
  --manifest examples/support-agent.manifest.json \
  --profile examples/mcp-profiles/review-required-support-profile.json \
  --output-dir artifacts/mcp-review \
  --exit-on-review
```

The second fixture intentionally declares an HTTP profile without an authorization expectation, maps a tool to the wrong action class, and maps another tool to an undeclared manifest tool. It writes artifacts and exits `1` only because `--exit-on-review` is requested.

## Findings

| Identifier | Review condition | What to review |
|---|---|---|
| `TW-MCP-001` | An HTTP profile declares `authorization_expected: false`. | Whether unauthenticated access is intentional and whether the trust boundary has sufficient compensating controls. |
| `TW-MCP-002` | An MCP tool maps to a manifest tool that does not exist. | Whether the manifest is incomplete, the mapping is wrong, or an undeclared capability was introduced. |
| `TW-MCP-003` | The profile action class differs from the mapped manifest-tool action class. | Whether the capability was classified correctly and whether applicable policy coverage remains correct. |

A finding is a reviewer prompt, not a protocol failure, vulnerability verdict, or runtime block.

## CI gate pattern

Use a clear profile as a standard quality-gate step. Use a review-required fixture only to prove that the gate reports a nonzero status when expected.

```bash
set +e
trustweave mcp-profile-check \
  --manifest examples/support-agent.manifest.json \
  --profile examples/mcp-profiles/review-required-support-profile.json \
  --output-dir artifacts/mcp-review \
  --exit-on-review
review_exit=$?
set -e

test "$review_exit" -eq 1
grep -q 'TW-MCP-001' artifacts/mcp-review/mcp-profile-review.json
```

## Limits

The profile review does not verify a server URI’s reachability, host ownership, certificates, OAuth discovery document, dynamic registration, token audience, token storage, authorization code flow, PKCE, user consent, tool schema, server capability, or action result. It creates no network traffic and retains no credentials. Review a real integration with the organization’s authorization, identity, deployment, and runtime-control processes.
