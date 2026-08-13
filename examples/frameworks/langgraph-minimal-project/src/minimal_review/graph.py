"""Minimal LangGraph-style declaration source for static TrustWeave example provenance.

This file is deliberately never imported, compiled, or executed by TrustWeave. It contains no
model client, tool, network operation, credential, or external endpoint.
"""

from __future__ import annotations


def route_declared_boundary(state: dict[str, str]) -> dict[str, str]:
    """Return a symbolic review state for a framework project that is never run in this repo."""

    return {"review": state.get("review", "declared")}


# The reference in langgraph.json points to this symbolic exported graph name. A real LangGraph
# runtime would compile a graph object here; TrustWeave intentionally does neither operation.
graph = route_declared_boundary
