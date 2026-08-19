# Developer integration routes

TrustWeave works from **local declarations and already-recorded metadata**. Choose the route that matches the files you already have; every command below reads a local input and writes local deterministic evidence. None installs a framework, imports application code, executes an agent or tool, connects to an MCP server, calls a model, reads credentials, or publishes an artifact.

## Choose a local input

| You already have | Start with | What TrustWeave produces | What it does not establish |
| --- | --- | --- | --- |
| An Agent Security Manifest and policy | [`scan`](CLI.md) and [`test`](CLI.md) | A bundle of declared-flow decisions and synthetic policy results | Runtime behavior, deployment approval, or an agent-security verdict |
| A LangGraph `langgraph.json` descriptor | `framework-import --framework langgraph` | A normalized local framework inventory | Graph import, compilation, execution, or environment loading |
| An exported OpenAI Agents descriptor | `framework-import --framework openai-agents` | A normalized local framework inventory | SDK installation, model calls, tool calls, or MCP access |
| A JSON-compatible CrewAI agents/tasks snapshot | `framework-import --framework crewai` | A normalized local framework inventory | Crew/task execution, guardrail evaluation, or tool resolution |
| A saved MCP `tools/list` response | `mcp-import` | A stable local MCP tool inventory | Server discovery, connection, authentication, or tool invocation |
| A repository CI job | The [local CI workflow](CI_WORKFLOW.md) | Deterministic evidence generated inside your chosen runner | Artifact publishing, SARIF upload, or an automatic merge/deployment decision |

## Copy-paste local examples

Run these commands from a TrustWeave source checkout after completing the [installation and five-minute local review](INSTALLATION.md).

```shell
# Read a checked-in LangGraph-style descriptor without importing Python code.
trustweave framework-import \
  --framework langgraph \
  --input examples/frameworks/langgraph-minimal-project/langgraph.json \
  --output-dir artifacts/langgraph-minimal

# Normalize a locally exported OpenAI Agents descriptor without installing its SDK.
trustweave framework-import \
  --framework openai-agents \
  --input examples/frameworks/openai-agents-descriptor.json \
  --output-dir artifacts/openai-agents

# Normalize a saved MCP tools/list snapshot without contacting an MCP server.
trustweave mcp-import \
  --tool-list examples/mcp-tools/support-tools-list.json \
  --output-dir artifacts/mcp-inventory
```

Use `python -m trustweave` in place of `trustweave` when you prefer a Python module invocation. Both entry points expose the same command surface.

## Continue from the inventory

A framework or MCP inventory is **review input**, not an Agent Security Manifest. A human reviewer must still classify tools, define sources and flows, select deterministic policy, and run a normal local review. Continue with the [manifest contract](MANIFEST_CONTRACT.md), [policy review](POLICY_REVIEW.md), and [local CI workflow](CI_WORKFLOW.md).

For accepted input shapes, output contracts, and framework-specific limits, see the source guides: [framework declaration import](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/FRAMEWORK_IMPORT.md) and [local MCP tools-list import](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/MCP_IMPORT.md).
