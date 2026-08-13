# Non-Executing Framework Proof Walkthrough

This walkthrough demonstrates TrustWeave’s static declaration adapters for **LangGraph**, **OpenAI Agents SDK**, and **CrewAI** using only committed local files. It is a proof of deterministic inventory normalization, not an execution test of any framework.

```bash
trustweave framework-import --framework langgraph --input examples/frameworks/langgraph.json --output-dir artifacts/langgraph
trustweave framework-import --framework openai-agents --input examples/frameworks/openai-agents-descriptor.json --output-dir artifacts/openai-agents
trustweave framework-import --framework crewai --input examples/frameworks/crewai-crew.json --output-dir artifacts/crewai
```

Each command writes a `framework-inventory.json` with literal declared graph, agent, task, and tool labels. The generic fixture inputs contain no secrets, endpoints, handlers, prompt payloads, or executable code.

For a declaration traced to a checked-in project-style LangGraph layout rather than a generic snapshot, run:

```bash
trustweave framework-import \
  --framework langgraph \
  --input examples/frameworks/langgraph-minimal-project/langgraph.json \
  --output-dir artifacts/langgraph-minimal
```

The accompanying [provenance note](../examples/frameworks/langgraph-minimal-project/PROVENANCE.md) explains the source layout and its limits. TrustWeave reads only the JSON configuration; it does not install or import the example, compile a graph, or execute any framework code.

| Adapter | Local input proof | What the inventory proves | What it does not prove |
|---|---|---|---|
| LangGraph | `langgraph.json` graph references, plus one checked-in project-style configuration example | The declaration contains named graph references. | Graph compilation, dependency resolution, environment loading, tool discovery, or execution. |
| OpenAI Agents SDK | Explicit static agent descriptor | The supplied descriptor names agents and tool labels. | Importing an `Agent`, calling a model, using hosted tools, or invoking a tool. |
| CrewAI | JSON-compatible agents/tasks snapshot | The snapshot has declared agents, tasks, assignments, and tool labels. | Loading a Crew, resolving guardrails, executing a task, or processing output. |

The inventories are deliberately not Agent Security Bundles and do not infer TrustWeave action classes, policy decisions, authorization, runtime reachability, or security posture. A reviewer must map declared framework artifacts into an explicit TrustWeave manifest and policy before running the ordinary local `scan`, `test`, `diff`, and review workflows.
