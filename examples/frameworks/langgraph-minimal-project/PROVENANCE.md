# Minimal LangGraph-Style Project Provenance

## What this example is

This directory is a small, checked-in **source-only** project layout used to demonstrate how TrustWeave reads a supplied `langgraph.json` declaration. It was created from the configuration concepts documented in the LangGraph application-structure guide: a project configuration identifies dependencies and one or more named graph references.[1]

The example contains one symbolic graph reference:

```json
{"boundary_review": "./src/minimal_review/graph.py:graph"}
```

That reference resolves to a checked-in source path. It is intentionally useful as provenance for a declaration review because a reviewer can inspect both the declaration and the referenced source path without TrustWeave having to load either one.

## What TrustWeave reads

```bash
trustweave framework-import \
  --framework langgraph \
  --input examples/frameworks/langgraph-minimal-project/langgraph.json \
  --output-dir artifacts/langgraph-minimal
```

The command reads the local JSON document and records the literal declared graph name and reference in `framework-inventory.json`.

## What it does not do

TrustWeave does **not** install the example dependency, import `minimal_review.graph`, compile a LangGraph graph, instantiate an agent, run a node, call a model, use a tool, read an environment variable, access a credential, or send network traffic. The `pyproject.toml` and Python source are committed only to make the declaration shape and file reference reviewable.

This example is not a claim that TrustWeave understands LangGraph runtime semantics, validates a deployment, or establishes that a graph is secure. It is evidence that the static adapter normalizes a real project-style `langgraph.json` layout without execution.

## Maintenance rule

If LangGraph changes the documented declaration shape used here, update this example, its tests, and the framework-proof walkthrough together. Do not silently alter the provenance claim or replace it with a hand-authored descriptor without explaining the change.

## Reference

[1]: https://docs.langchain.com/oss/python/langgraph/application-structure "LangGraph application structure"
