"""Bounded static analysis of supplied declared trust-boundary chains."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from trustweave.findings import finding as canonical_finding
from trustweave.models import ValidationError, reject_unknown_fields
from trustweave.provenance import add_generated_at

CHAIN_MANIFEST_SCHEMA_VERSION = "trustweave.dev/chain-manifest/v1alpha1"
CHAIN_REVIEW_SCHEMA_VERSION = "trustweave.dev/chain-review/v1alpha1"
VALID_NODE_KINDS = frozenset({"source", "data", "tool", "sink", "sanitizer", "approval"})
VALID_ACTION_CLASSES = frozenset({"read", "write", "sensitive", "external"})
SENSITIVE_CLASSIFICATIONS = frozenset({"confidential", "restricted"})


@dataclass(frozen=True)
class ChainNode:
    """One reviewer-declared node; no behavior is inferred from its identifier or description."""

    identifier: str
    kind: str
    trust: str | None
    classification: str | None
    action_class: str | None
    fail_closed: bool | None
    covers_classifications: tuple[str, ...]


@dataclass(frozen=True)
class _TraversalState:
    """Bounded local propagation state for one explicitly declared chain path."""

    node: str
    path: tuple[str, ...]
    classifications: frozenset[str]
    approved_classifications: frozenset[str]
    incomplete_sanitizers: tuple[tuple[str, tuple[str, ...]], ...]


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    return value


def _sequence(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError(f"{path} must be a list")
    return value


def _parse_chain_manifest(
    document: Mapping[str, Any],
) -> tuple[dict[str, ChainNode], dict[str, tuple[str, ...]]]:
    root = _mapping(document, "chain_manifest")
    reject_unknown_fields(root, {"schema_version", "name", "nodes", "edges"}, "chain_manifest")
    if root.get("schema_version") != CHAIN_MANIFEST_SCHEMA_VERSION:
        raise ValidationError(
            f"chain_manifest.schema_version must be {CHAIN_MANIFEST_SCHEMA_VERSION}"
        )
    _text(root.get("name"), "chain_manifest.name")
    nodes: dict[str, ChainNode] = {}
    for index, raw_node in enumerate(_sequence(root.get("nodes"), "chain_manifest.nodes")):
        path = f"chain_manifest.nodes[{index}]"
        node = _mapping(raw_node, path)
        reject_unknown_fields(
            node,
            {
                "id",
                "kind",
                "trust",
                "classification",
                "action_class",
                "fail_closed",
                "covers_classifications",
            },
            path,
        )
        identifier = _text(node.get("id"), f"{path}.id")
        if identifier in nodes:
            raise ValidationError(f"chain_manifest.nodes contains duplicate id: {identifier}")
        kind = _text(node.get("kind"), f"{path}.kind")
        if kind not in VALID_NODE_KINDS:
            raise ValidationError(f"{path}.kind must be one of {sorted(VALID_NODE_KINDS)}")
        allowed_fields_by_kind = {
            "source": {"id", "kind", "trust", "classification"},
            "data": {"id", "kind", "classification"},
            "tool": {"id", "kind", "action_class"},
            "sink": {"id", "kind", "action_class"},
            "approval": {"id", "kind", "fail_closed"},
            "sanitizer": {"id", "kind", "covers_classifications"},
        }
        for field in sorted(set(node) - allowed_fields_by_kind[kind]):
            raise ValidationError(f"{path}.{field} is not valid for {kind} nodes")
        trust = node.get("trust")
        if trust is not None and trust not in {"trusted", "untrusted", "conditional"}:
            raise ValidationError(f"{path}.trust must be a declared trust label")
        classification = node.get("classification")
        if classification is not None:
            classification = _text(classification, f"{path}.classification")
        action_class = node.get("action_class")
        if action_class is not None and action_class not in VALID_ACTION_CLASSES:
            raise ValidationError(
                f"{path}.action_class must be one of {sorted(VALID_ACTION_CLASSES)}"
            )
        fail_closed = node.get("fail_closed")
        if fail_closed is not None and not isinstance(fail_closed, bool):
            raise ValidationError(f"{path}.fail_closed must be a boolean")
        covers = tuple(
            _text(value, f"{path}.covers_classifications")
            for value in _sequence(
                node.get("covers_classifications", []), f"{path}.covers_classifications"
            )
        )
        if kind == "source" and trust is None:
            raise ValidationError(f"{path}.trust is required for source nodes")
        if kind == "data" and classification is None:
            raise ValidationError(f"{path}.classification is required for data nodes")
        if kind in {"tool", "sink"} and action_class is None:
            raise ValidationError(f"{path}.action_class is required for {kind} nodes")
        if kind == "approval" and fail_closed is None:
            raise ValidationError(f"{path}.fail_closed is required for approval nodes")
        if kind == "sanitizer" and not covers:
            raise ValidationError(f"{path}.covers_classifications is required for sanitizer nodes")
        if len(set(covers)) != len(covers):
            raise ValidationError(
                f"{path}.covers_classifications must not contain duplicate classifications"
            )
        nodes[identifier] = ChainNode(
            identifier,
            kind,
            trust,
            classification,
            action_class,
            fail_closed,
            tuple(sorted(set(covers))),
        )
    if not nodes:
        raise ValidationError("chain_manifest.nodes must not be empty")
    edges: dict[str, set[str]] = defaultdict(set)
    for index, raw_edge in enumerate(_sequence(root.get("edges"), "chain_manifest.edges")):
        path = f"chain_manifest.edges[{index}]"
        edge = _mapping(raw_edge, path)
        reject_unknown_fields(edge, {"from", "to"}, path)
        origin = _text(edge.get("from"), f"{path}.from")
        target = _text(edge.get("to"), f"{path}.to")
        if origin not in nodes or target not in nodes:
            raise ValidationError(f"{path} references an unknown declared node")
        edges[origin].add(target)
    return nodes, {node: tuple(sorted(targets)) for node, targets in edges.items()}


def _finding(
    identifier: str, severity: str, message: str, path: tuple[str, ...], **properties: Any
) -> dict[str, Any]:
    """Build a bounded canonical finding for a supplied declared chain path."""

    return canonical_finding(
        identifier,
        severity,
        message,
        "declared_chain_configuration",
        subject={"path": path},
        location={"path_identity": " -> ".join(path) or "analysis_budget"},
        properties=properties,
    )


def _advance_state(state: _TraversalState, node: ChainNode) -> _TraversalState:
    """Apply the next declared node's static contract to a local traversal state."""

    classifications = state.classifications
    approved_classifications = state.approved_classifications
    incomplete_sanitizers = state.incomplete_sanitizers
    if node.classification in SENSITIVE_CLASSIFICATIONS:
        classifications = classifications | {node.classification}
    if node.kind == "approval" and node.fail_closed is True and classifications:
        approved_classifications = classifications
    if node.kind == "sanitizer" and classifications:
        missing = tuple(sorted(classifications - set(node.covers_classifications)))
        if missing:
            incomplete_sanitizers = (*incomplete_sanitizers, (node.identifier, missing))
        covered = set(node.covers_classifications)
        classifications = classifications - covered
        approved_classifications = approved_classifications - covered
    return _TraversalState(
        node=state.node,
        path=state.path,
        classifications=frozenset(classifications),
        approved_classifications=frozenset(approved_classifications),
        incomplete_sanitizers=incomplete_sanitizers,
    )


def review_declared_chains(
    document: Mapping[str, Any],
    generated_at: str | None = None,
    *,
    max_nodes: int = 1000,
    max_paths: int = 1000,
    max_edges: int = 5000,
    max_depth: int = 100,
    max_states: int = 5000,
) -> dict[str, Any]:
    """Review declared paths with deterministic, bounded propagation of local static metadata."""

    budgets = {
        "max_nodes": max_nodes,
        "max_paths": max_paths,
        "max_edges": max_edges,
        "max_depth": max_depth,
        "max_states": max_states,
    }
    if any(value < 1 for value in budgets.values()):
        raise ValidationError("chain analysis budgets must be positive")
    nodes, edges = _parse_chain_manifest(document)
    findings: list[dict[str, Any]] = []
    terminals: dict[tuple[str, ...], _TraversalState] = {}
    budget_name: str | None = "max_nodes" if len(nodes) > max_nodes else None
    edges_traversed = 0
    states_explored = 0
    if budget_name is None:
        starts = sorted(node.identifier for node in nodes.values() if node.trust == "untrusted")
        stack: list[_TraversalState] = [
            _TraversalState(start, (start,), frozenset(), frozenset(), ())
            for start in reversed(starts)
        ]
        seen_states: set[
            tuple[
                str,
                tuple[str, ...],
                frozenset[str],
                frozenset[str],
                tuple[tuple[str, tuple[str, ...]], ...],
            ]
        ] = set()
        while stack and budget_name is None:
            state = stack.pop()
            node = nodes[state.node]
            state = _advance_state(state, node)
            identity = (
                state.node,
                state.path,
                state.classifications,
                state.approved_classifications,
                state.incomplete_sanitizers,
            )
            if identity in seen_states:
                continue
            if states_explored >= max_states:
                budget_name = "max_states"
                break
            seen_states.add(identity)
            states_explored += 1
            if node.action_class == "external":
                if state.path not in terminals and len(terminals) >= max_paths:
                    budget_name = "max_paths"
                    break
                terminals[state.path] = state
                continue
            for target in reversed(edges.get(state.node, ())):
                if len(state.path) >= max_depth:
                    budget_name = "max_depth"
                    break
                if edges_traversed >= max_edges:
                    budget_name = "max_edges"
                    break
                edges_traversed += 1
                stack.append(
                    _TraversalState(
                        target,
                        state.path + (target,),
                        state.classifications,
                        state.approved_classifications,
                        state.incomplete_sanitizers,
                    )
                )

    for path, state in sorted(terminals.items()):
        classifications = sorted(state.classifications)
        if not classifications:
            continue
        findings.append(
            _finding(
                "TW-CHAIN-001",
                "high",
                (
                    "An explicitly declared untrusted path reaches sensitive data and an "
                    "external action."
                ),
                path,
                classifications=classifications,
            )
        )
        unapproved = sorted(set(classifications) - set(state.approved_classifications))
        if unapproved:
            findings.append(
                _finding(
                    "TW-CHAIN-002",
                    "high",
                    (
                        "The declared sensitive-data path reaches an external action without a "
                        "declared fail-closed approval boundary."
                    ),
                    path,
                    classifications=unapproved,
                )
            )
        for sanitizer, missing in state.incomplete_sanitizers:
            findings.append(
                _finding(
                    "TW-CHAIN-003",
                    "medium",
                    (
                        "A declared sanitizer does not list coverage for every propagated "
                        "sensitive classification."
                    ),
                    path,
                    classifications=list(missing),
                    sanitizer=sanitizer,
                )
            )
    if budget_name is not None:
        findings.append(
            _finding(
                "TW-CHAIN-004",
                "medium",
                "The declared graph analysis budget was exceeded; the local review is incomplete.",
                (),
                budget=budget_name,
                **budgets,
            )
        )
    paths = sorted(terminals)
    review: dict[str, Any] = {
        "schema_version": CHAIN_REVIEW_SCHEMA_VERSION,
        "findings": findings,
        "paths": [{"identity": list(path)} for path in paths],
        "summary": {
            "declared_nodes": len(nodes),
            "review_findings": len(findings),
            "paths": len(paths),
            "edges_traversed": edges_traversed,
            "states_explored": states_explored,
        },
        "limits": [
            (
                "Chain findings reflect only supplied declared nodes, edges, and bounded static "
                "metadata propagation. They do not prove a runtime data path, tool behavior, "
                "vulnerability, or deployed control state."
            )
        ],
    }
    return add_generated_at(review, generated_at)


def render_chain_review(review: Mapping[str, Any]) -> str:
    """Render a bounded local chain-review summary without adding external evidence."""

    paths = _sequence(review.get("paths"), "chain_review.paths")
    findings = _sequence(review.get("findings"), "chain_review.findings")
    lines = ["# Declared Chain Review", "", "## Declared paths", ""]
    if paths:
        lines.extend(
            f"- `{' -> '.join(_sequence(_mapping(path, 'path').get('identity'), 'path.identity'))}`"
            for path in paths
        )
    else:
        lines.append(
            "- No path from an explicitly declared untrusted source reached an external action."
        )
    lines.extend(["", "## Review findings", ""])
    if findings:
        lines.extend(
            f"- **{_mapping(finding, 'finding').get('id')}** "
            f"({_mapping(finding, 'finding').get('severity')}): "
            f"{_mapping(finding, 'finding').get('message')}"
            for finding in findings
        )
    else:
        lines.append("- No reviewer-facing findings were produced from the supplied declarations.")
    lines.extend(
        [
            "",
            "> This report reviews supplied declared graph metadata only. It does not demonstrate "
            "a runtime path, exploitability, or deployed control behavior.",
            "",
        ]
    )
    return "\n".join(lines)
