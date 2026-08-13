"""Bounded static analysis of supplied declared trust-boundary chains."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from trustweave.models import ValidationError, reject_unknown_fields
from trustweave.provenance import add_generated_at

CHAIN_MANIFEST_SCHEMA_VERSION = "trustweave.dev/chain-manifest/v1alpha1"
CHAIN_REVIEW_SCHEMA_VERSION = "trustweave.dev/chain-review/v1alpha1"
VALID_NODE_KINDS = frozenset({"source", "data", "tool", "output", "sink", "sanitizer", "approval"})
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
        if kind not in {"approval"} and fail_closed is not None:
            raise ValidationError(f"{path}.fail_closed is only valid for approval nodes")
        if kind not in {"sanitizer"} and covers:
            raise ValidationError(
                f"{path}.covers_classifications is only valid for sanitizer nodes"
            )
        if kind in {"source", "data", "approval", "sanitizer"} and action_class is not None:
            raise ValidationError(f"{path}.action_class is not valid for {kind} nodes")
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
    result: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "message": message,
        "evidence_kind": "declared_chain_configuration",
        "subject": {"path": list(path)},
        "location": {"path_identity": " -> ".join(path)},
    }
    if properties:
        result["properties"] = properties
    return result


def review_declared_chains(
    document: Mapping[str, Any],
    generated_at: str | None = None,
    *,
    max_nodes: int = 1000,
    max_paths: int = 1000,
) -> dict[str, Any]:
    """Review only explicitly declared graph paths within deterministic node and path budgets."""

    if max_nodes < 1 or max_paths < 1:
        raise ValidationError("chain analysis budgets must be positive")
    nodes, edges = _parse_chain_manifest(document)
    findings: list[dict[str, Any]] = []
    paths: set[tuple[str, ...]] = set()
    budget_exceeded = len(nodes) > max_nodes
    if not budget_exceeded:
        starts = sorted(node.identifier for node in nodes.values() if node.trust == "untrusted")
        for start in starts:
            stack: list[tuple[str, tuple[str, ...]]] = [(start, (start,))]
            while stack and not budget_exceeded:
                current, path = stack.pop()
                node = nodes[current]
                if node.action_class == "external":
                    paths.add(path)
                    if len(paths) > max_paths:
                        budget_exceeded = True
                        break
                    continue
                for target in reversed(edges.get(current, ())):
                    if target not in path:
                        stack.append((target, path + (target,)))
    for path in sorted(paths):
        path_nodes = tuple(nodes[identifier] for identifier in path)
        classifications = tuple(
            node.classification
            for node in path_nodes
            if node.classification in SENSITIVE_CLASSIFICATIONS
        )
        external = path_nodes[-1].action_class == "external"
        if not classifications or not external:
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
                classifications=sorted(set(classifications)),
            )
        )
        approval_after_sensitive = any(
            node.kind == "approval" and node.fail_closed is True
            for node in path_nodes[
                min(
                    index
                    for index, node in enumerate(path_nodes)
                    if node.classification in SENSITIVE_CLASSIFICATIONS
                ) :
            ]
        )
        if not approval_after_sensitive:
            findings.append(
                _finding(
                    "TW-CHAIN-002",
                    "high",
                    (
                        "The declared sensitive-data path reaches an external action without a "
                        "declared fail-closed approval boundary."
                    ),
                    path,
                )
            )
        for node in path_nodes:
            if node.kind == "sanitizer" and not set(classifications).issubset(
                node.covers_classifications
            ):
                findings.append(
                    _finding(
                        "TW-CHAIN-003",
                        "medium",
                        (
                            "A declared sanitizer does not list coverage for every propagated "
                            "sensitive classification."
                        ),
                        path,
                        classifications=sorted(set(classifications)),
                        sanitizer=node.identifier,
                    )
                )
    if budget_exceeded:
        findings.append(
            _finding(
                "TW-CHAIN-004",
                "medium",
                "The declared graph analysis budget was exceeded; the local review is incomplete.",
                (),
                max_nodes=max_nodes,
                max_paths=max_paths,
            )
        )
    review: dict[str, Any] = {
        "schema_version": CHAIN_REVIEW_SCHEMA_VERSION,
        "findings": findings,
        "paths": [{"identity": list(path)} for path in sorted(paths)],
        "summary": {
            "declared_nodes": len(nodes),
            "review_findings": len(findings),
            "paths": len(paths),
        },
        "limits": [
            (
                "Chain findings reflect only supplied declared nodes and edges. They do not "
                "prove a runtime data path, tool behavior, vulnerability, or deployed control "
                "state."
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
