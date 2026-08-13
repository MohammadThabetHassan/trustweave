"""Static, non-executing importers for user-supplied framework declaration snapshots."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from trustweave.models import ValidationError

FRAMEWORK_INVENTORY_SCHEMA_VERSION = "trustweave.dev/framework-inventory/v1alpha1"
SUPPORTED_FRAMEWORKS = frozenset({"langgraph", "openai-agents", "crewai"})


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    return value


def _items(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValidationError(f"{path} must be a list")
    return value


def _unique_names(entries: Sequence[Mapping[str, Any]], path: str) -> list[str]:
    names: list[str] = []
    for index, entry in enumerate(entries):
        name = _text(entry.get("name"), f"{path}[{index}].name")
        if name in names:
            raise ValidationError(f"{path} contains duplicate name: {name}")
        names.append(name)
    return names


def _tools(value: Any, path: str) -> list[str]:
    if value is None:
        return []
    names = [_text(item, f"{path}[{index}]") for index, item in enumerate(_items(value, path))]
    if len(names) != len(set(names)):
        raise ValidationError(f"{path} contains duplicate tool names")
    return sorted(names)


def _langgraph(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    graphs = _object(document.get("graphs"), "langgraph.graphs")
    if not graphs:
        raise ValidationError("langgraph.graphs must include at least one graph")
    entries: list[dict[str, Any]] = []
    for name, reference in graphs.items():
        entries.append(
            {
                "kind": "graph",
                "name": _text(name, "langgraph.graphs key"),
                "reference": _text(reference, f"langgraph.graphs.{name}"),
            }
        )
    return sorted(entries, key=lambda entry: str(entry["name"]))


def _openai_agents(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    agents = [
        _object(item, f"openai_agents.agents[{index}]")
        for index, item in enumerate(_items(document.get("agents"), "openai_agents.agents"))
    ]
    names = _unique_names(agents, "openai_agents.agents")
    entries: list[dict[str, Any]] = []
    for agent, name in zip(agents, names, strict=True):
        entries.append(
            {
                "kind": "agent",
                "name": name,
                "tools": _tools(agent.get("tools"), f"openai_agents.agents.{name}.tools"),
            }
        )
    return sorted(entries, key=lambda entry: str(entry["name"]))


def _crewai(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    agents = [
        _object(item, f"crewai.agents[{index}]")
        for index, item in enumerate(_items(document.get("agents"), "crewai.agents"))
    ]
    tasks = [
        _object(item, f"crewai.tasks[{index}]")
        for index, item in enumerate(_items(document.get("tasks"), "crewai.tasks"))
    ]
    agent_name_list = _unique_names(agents, "crewai.agents")
    agent_names = set(agent_name_list)
    task_names = _unique_names(tasks, "crewai.tasks")
    entries: list[dict[str, Any]] = [
        {
            "kind": "agent",
            "name": name,
            "tools": _tools(agent.get("tools"), f"crewai.agents.{name}.tools"),
        }
        for agent, name in zip(agents, agent_name_list, strict=True)
    ]
    for task, name in zip(tasks, task_names, strict=True):
        agent_name = _text(task.get("agent"), f"crewai.tasks.{name}.agent")
        if agent_name not in agent_names:
            raise ValidationError(
                f"crewai.tasks.{name}.agent references unknown agent: {agent_name}"
            )
        entries.append(
            {
                "kind": "task",
                "name": name,
                "agent": agent_name,
                "tools": _tools(task.get("tools"), f"crewai.tasks.{name}.tools"),
            }
        )
    return sorted(entries, key=lambda entry: (str(entry["kind"]), str(entry["name"])))


def normalize_framework_declaration(framework: str, document: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize framework declarations supplied as local data without loading framework code."""

    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValidationError(f"Unsupported framework: {framework}")
    entries = {
        "langgraph": _langgraph,
        "openai-agents": _openai_agents,
        "crewai": _crewai,
    }[framework](document)
    return {
        "schema_version": FRAMEWORK_INVENTORY_SCHEMA_VERSION,
        "framework": framework,
        "entries": entries,
        "summary": {
            "entry_count": len(entries),
            "agent_count": sum(entry["kind"] == "agent" for entry in entries),
            "task_count": sum(entry["kind"] == "task" for entry in entries),
            "graph_count": sum(entry["kind"] == "graph" for entry in entries),
        },
        "limits": [
            (
                "TrustWeave read only the supplied local declaration snapshot. It did not import "
                "Python modules, install dependencies, load environment variables, compile a "
                "graph, instantiate an agent, or run a framework."
            ),
            (
                "Names, references, and declared tools are review metadata only. This inventory "
                "does not infer TrustWeave action classes, authorization, runtime reachability, "
                "or security."
            ),
        ],
    }
