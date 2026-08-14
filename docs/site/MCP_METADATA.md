# MCP metadata workflows

`trustweave mcp-profile-check` reviews a supplied **local metadata profile** against an Agent Security Manifest. It asks whether declared MCP-tool mappings, action classes, transport metadata, and authorization expectations are consistent with the manifest.

```shell
trustweave mcp-profile-check \
  --manifest examples/support-agent.manifest.json \
  --profile examples/mcp-profiles/clear-support-profile.json \
  --output-dir artifacts/mcp-clear \
  --exit-on-review
```

A profile describes transport (`http` or `stdio`), an identifier-like resource URI for HTTP profiles, an `authorization_expected` design expectation, and explicit mappings from MCP tool names to manifest tools. HTTP metadata rejects embedded credentials, query parameters, and fragments.

| Finding | Local review condition |
| --- | --- |
| `TW-MCP-001` | An HTTP profile declares that authorization is not expected |
| `TW-MCP-002` | A mapped manifest tool is not declared |
| `TW-MCP-003` | A mapped action class differs from the manifest tool’s action class |

Use the review-required fixture only to test intentional CI gate behavior. It produces local evidence and returns exit status `1` when `--exit-on-review` is requested.

> The command does not discover a server, open a transport, retrieve metadata, negotiate capabilities, perform OAuth, read a token, validate an audience claim, or call an MCP tool. Its profile is local declaration data, not proof of a live integration or runtime authorization.
