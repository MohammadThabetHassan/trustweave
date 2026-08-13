# Static Framework Declaration Import

`trustweave framework-import` normalizes an **already-provided local declaration snapshot** into `framework-inventory.json`. It supports three bounded formats: LangGraph `langgraph.json` graph references, an explicitly exported OpenAI Agents descriptor, and a JSON-compatible CrewAI agents/tasks snapshot.

```bash
trustweave framework-import --framework langgraph --input examples/frameworks/langgraph.json
trustweave framework-import --framework openai-agents --input examples/frameworks/openai-agents-descriptor.json
trustweave framework-import --framework crewai --input examples/frameworks/crewai-crew.json
```

| Framework | Accepted local data | Deliberate boundary |
|---|---|---|
| LangGraph | Literal `graphs` names and string references from `langgraph.json`. | No module import, dependency resolution, environment loading, graph compilation, or graph execution. |
| OpenAI Agents SDK | Explicit user-exported `agents` descriptor with names and string tool labels. | No Python object import, SDK installation, model call, tool call, hosted tool, or MCP connection. |
| CrewAI | JSON-compatible `agents` and `tasks` declarations with literal tool labels. | No Crew import, task execution, guardrail evaluation, tool resolution, or output processing. |

The inventory is a review aid only. It never infers a TrustWeave action class, policy decision, authorization, runtime reachability, or security conclusion. Framework documentation describes LangGraph configuration graph references, OpenAI Agents tool action surfaces, and CrewAI agent/task declarations; the importer intentionally reads only local literal data rather than running those ecosystems.[1] [2] [3]

## Provenance-backed LangGraph-style example

The checked-in [`langgraph-minimal-project`](../examples/frameworks/langgraph-minimal-project/) is a minimal project layout containing a real project-style `langgraph.json`, a matching symbolic source path, and a [provenance note](../examples/frameworks/langgraph-minimal-project/PROVENANCE.md). Reproduce its static inventory with:

```bash
trustweave framework-import \
  --framework langgraph \
  --input examples/frameworks/langgraph-minimal-project/langgraph.json \
  --output-dir artifacts/langgraph-minimal
```

TrustWeave reads only `langgraph.json`. It does not install the example, import its Python module, compile a graph, instantiate an agent, execute a node, load an environment variable, access a credential, or contact an external service. The example strengthens declaration provenance; it is not runtime integration or deployment validation.

## References

[1]: https://docs.langchain.com/oss/python/langgraph/application-structure "LangGraph application structure"
[2]: https://openai.github.io/openai-agents-python/tools/ "OpenAI Agents SDK tools"
[3]: https://docs.crewai.com/v1.15.14/en/concepts/tasks "CrewAI tasks and JSONC configuration"
